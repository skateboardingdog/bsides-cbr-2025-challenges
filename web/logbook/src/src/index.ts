import { serve } from '@hono/node-server'
import { randomUUID } from 'crypto'
import { readFile, writeFile, stat, access } from 'fs/promises'
import { Hono } from 'hono'
import { join } from 'path'
import { DATA_DIR } from './const.js'
import { getConnInfo } from '@hono/node-server/conninfo'

const app = new Hono();

// it's slow when there's a lot of users
const TIMEOUT = () => ({ signal: AbortSignal.timeout(1000) });

app.get('/', (c) => {
  return c.html(`
    <h1>Welcome to the Skateboarding Dog Logbook!<h1>
    <form action="/book" method="POST">
      <button type="submit">Create a Logbook</button>
    </form>
  `);
})

app.post("/book", async (c) => {
  const id = randomUUID();
  const file = join(DATA_DIR, id);
  await writeFile(file, "<h1>Logbook</h1>\n", { flag: 'a' });
  return c.redirect(`/book/${id}`)
});

app.get('/book/:id', async (c) => {
  const id = c.req.param('id');
  const file = join(DATA_DIR, id);
  try {
    const fStat = await stat(file);
    if (!fStat.isFile()) {
      throw new Error("not found");
    }
  } catch (e) {
    c.status(404);
    return c.html('<h1>Logbook not found</h1>');
  }
  c.res.headers.append('content-type', 'text/html');
  try {
    const data = (await readFile(file, TIMEOUT())).toString();
    return c.body(data + `
      <form method="POST">
        <b>Leave a Message</b>
        <br/>
        <label for="message">Message</label>
        <input name="message" type="text" />
        <button type="submit">Add a Message</button>
      </form>
    `);
  } catch (e) {
    c.status(404);
    return c.html('<h1>Logbook not found</h1>');
  }
});

app.post('/book/:id', async (c) => {
  const id = c.req.param('id');
  const file = join(DATA_DIR, id);
  try {
    await access(file);
    const fStat = await stat(file);
    if (!fStat.isFile()) {
      throw new Error("not found");
    }
  } catch (error) {
    c.status(404);
    return c.html('<h1>Logbook not found</h1>');
  }
  const b: { message: string } = await c.req.parseBody();
  if (b.message.length > 256) {
    return c.html("<h1>no hacking pls</h1>");
  }
  await writeFile(file, `
    <p>
      <b>${getConnInfo(c).remote.address}</b>: - ${b.message}
    </p>`, { flag: 'a', ...TIMEOUT() });
  return c.redirect(`/book/${id}`);
});


serve({
  fetch: app.fetch,
  port: 3000,
  hostname: "::"
}, (info) => {
  console.log(`Server is running on http://[::]:${info.port}`)
})
