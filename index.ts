import { createWriteStream, mkdirSync, rmSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { Stream } from 'node:stream';
import axios from 'axios';
import extract from 'extract-zip';
import pMap from 'p-map';

const blocks = [
  {
    id: '4e4a7ec8-6011-4751-a5ba-746eb065f6e3',
    spaceId: '33f1c42a-d4a2-49be-8079-cedeb6dd99b9',
    dirName: 'Challenges',
    recursive: true,
  },
  {
    id: '393ef7ec-d3de-410d-97398642dce6f44a',
    spaceId: '33f1c42a-d4a2-49be-8079-cedeb6dd99b9',
    dirName: 'Toturials',
    recursive: true,
  },
  
];

if (!process.env.NOTION_TOKEN) {
  console.error(
    'Environment variable NOTION_TOKEN is missing. Check the README.md for more information.',
  );
  process.exit(1);
}

type BlockTask = {
  id: string;
  state: string | null;
  status: {
    pagesExported: number | null;
    exportURL: string | null;
  };
};

type Task = {
  id: string;
  state: string | null;
  status?: {
    pagesExported: number | null;
    exportURL: string | null;
  };
};

const client = axios.create({
  // Notion unofficial API
  baseURL: 'https://www.notion.so/api/v3',
  headers: {
    Cookie: `token_v2=${process.env.NOTION_TOKEN}`,
  },
});

function delay(ms: number) {
  console.log(
    `Waiting ${ms / 1000} second${ms > 1000 ? 's' : ''} before polling again...`,
  );
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

// Enqueue all export tasks immediately, without waiting for the
// export tasks to complete
const enqueuedBlocks = await pMap(blocks, async (block) => {
  const {
    data: { taskId },
  }: { data: { taskId: string } } = await client.post('enqueueTask', {
    task: {
      eventName: 'exportBlock',
      request: {
        block: {
          id: block.id,
          spaceId: block.spaceId,
        },
        exportOptions: {
          exportType: 'markdown',
          locale: 'en',
          timeZone: 'Europe/Vienna',
        },
        recursive: block.recursive,
      },
    },
  });

  if (!taskId) {
    throw new Error('No taskId returned from enqueueTask');
  }

  console.log(`Started export of block ${block.dirName} as task ${taskId}`);

  const task: BlockTask = {
    id: taskId,
    state: null,
    status: {
      pagesExported: null,
      exportURL: null,
    },
  };

  return {
    ...block,
    task: task,
  };
});

let retries = 0;

// eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
while (true) {
  const incompleteEnqueuedBlocks = enqueuedBlocks.filter(
    ({ task }) => task.state !== 'success',
  );

  const taskIds = incompleteEnqueuedBlocks.map(({ task }) => task.id);

  try {
    const {
      data: { results },
      headers: { 'set-cookie': getTasksRequestCookies },
    }: { data: { results: Task[] }; headers: { 'set-cookie': string[] } } =
      await client.post('getTasks', {
        taskIds: taskIds,
      });

    const blocksWithTaskProgress = results.reduce(
      (blocksAcc, task) => {
        const block = enqueuedBlocks.find(({ task: { id } }) => id === task.id);

        if (!block || !task.status) return blocksAcc;

        // Mutate original object in enqueuedBlocks for while loop
        // exit condition
        block.task.state = task.state;
        block.task.status.pagesExported = task.status.pagesExported;
        block.task.status.exportURL = task.status.exportURL;

        return blocksAcc.concat(block);
      },
      [] as typeof incompleteEnqueuedBlocks,
    );

    for (const block of blocksWithTaskProgress) {
      console.log(
        `Exported ${block.task.status.pagesExported} pages for ${block.dirName}`,
      );

      if (block.task.state === 'success') {
        const backupDirPath = path.join(
          process.cwd(),
          'exports',
          block.dirName,
        );

        const temporaryZipPath = path.join(
          process.cwd(),
          'exports',
          `${block.dirName}.zip`,
        );

        console.log(`Export finished for ${block.dirName}`);

        const response = await client<Stream>({
          method: 'GET',
          url: block.task.status.exportURL || undefined,
          responseType: 'stream',
          headers: {
            Cookie: getTasksRequestCookies.find((cookie) =>
              cookie.includes('file_token='),
            ),
          },
        });

        const sizeInMb =
          Number(response.headers['content-length']) / 1000 / 1000;
        console.log(`Downloading ${Math.round(sizeInMb * 1000) / 1000}mb...`);

        const stream = response.data.pipe(createWriteStream(temporaryZipPath));

        await new Promise((resolve, reject) => {
          stream.on('close', resolve);
          stream.on('error', reject);
        });

        rmSync(backupDirPath, { recursive: true, force: true });
        mkdirSync(backupDirPath, { recursive: true });
        await extract(temporaryZipPath, { dir: backupDirPath });
        unlinkSync(temporaryZipPath);

        console.log(`✅ Export of ${block.dirName} downloaded and unzipped`);
      }
    }

    // If all blocks are done, break out of the loop
    if (!enqueuedBlocks.find(({ task }) => task.state !== 'success')) {
      break;
    }

    // Reset retries on success
    retries = 0;
  } catch (error) {
    if (!axios.isAxiosError(error) || error.response?.status !== 429) {
      // Rethrow errors which do not contain an HTTP 429 status
      // code
      throw error;
    }

    console.log(
      'Received response with HTTP 429 (Too Many Requests), increasing delay...',
    );
    retries += 1;
  }

  // Rate limit polling, with incremental backoff
  await delay(1000 + 1000 * retries);
}

console.log('✅ All exports successful');
