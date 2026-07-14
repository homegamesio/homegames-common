# SquishJS Game Authoring — Technical Reference for Code Generation

> Context document for an LLM that writes Homegames games. Everything here is verified against `squishjs@1.4.2` (the `squish-142` alias), the server's real click/frame pipeline, and the shipped first-party catalog games. If you generate a game, follow this contract exactly. Code that violates the **Hard Constraints** section will be auto-rejected by the publishing pipeline before a human ever sees it.

---

## 1. What a Homegames game is

A Homegames game is a **single JavaScript class** that extends `Game` from a versioned SquishJS package. The server (`homegames-core`) instantiates the class, repeatedly serializes ("squishes") its scene graph into a compact binary form, and streams it to every connected browser client over WebSocket. Clients render the scene and send input (clicks, key presses) back to the server, which calls methods on your game instance.

Key mental model:

- **You never render or draw.** You build and mutate a tree of nodes (`Shape`, `Text`, `Asset`). The client draws them.
- **You never write networking.** The server multiplexes all players into one shared game instance. Player input arrives as method calls.
- **Your code runs in Node on the server, not in a browser.** There is no `window`, `document`, `location`, `alert`, `localStorage`, or DOM. A "play again" button that calls `location.reload()` throws a `ReferenceError` and crashes the session. Restart/replay is always done by **resetting your own state in place** — clear the relevant nodes, reset your variables, rebuild the play field.
- **The coordinate plane is `0–100` on both axes**, regardless of screen size or aspect ratio. `(0,0)` is top-left, `(100,100)` is bottom-right. Think percentages.
- **State changes are not automatic.** After you mutate a node, you must signal it (see §4). This is the #1 mistake — read §4 carefully.
- **The game is shared, not per-player.** One instance serves all players. Per-player visuals are done with `playerIds` (see §8), not separate instances.

---

## 2. Hard Constraints (your code is validated automatically)

The publish pipeline runs an AST scan, then loads and runs your game in a Docker sandbox for ~5 seconds. To pass:

1. **Entry point is `index.js`** and it must `module.exports = YourGameClass;` (a class, not an instance).
2. **`require` only the SquishJS package and your own local files.** Use `require('squish-142')`. Do **not** require Node built-ins (`fs`, `http`, `https`, `net`, `child_process`, `os`, `path`, `crypto`, `cluster`, `dgram`, etc.). Do not make network requests, touch the filesystem, spawn processes, or read `process.env`. Browser globals (`window`, `document`, `location`, `navigator`, `alert`) **do not exist** — referencing any of them throws at runtime.
3. **No dynamic code execution:** no `eval`, no `new Function(...)`, no `require(variable)`.
4. **`static metadata()` is required** and must return an object whose `squishVersion` matches the package you imported (`'142'` for `squish-142`).
5. **It must not throw** during `require`, construction, or the first few seconds of ticking. A crash = rejected. But note the sandbox's blind spot: **it never presses a key or clicks anything**, so code behind input handlers, `onClick`s, and phase gates (`if (!this.gameStarted) return;`) runs zero times during validation. A `ReferenceError` there sails through and crashes the game mid-session, the first time a real player triggers it. §15.1 tells you how to write that code so a typo can't hide in it.
6. **Size limits:** total game ≤ 20 MB, any single file ≤ 5 MB. Keep assets external (referenced by id), not inlined.
7. **License:** published games are GPLv3. A `LICENSE` file is required at publish time (not your concern when generating the game code itself, but don't add a conflicting license header).

Default to **`squish-142` / `squishVersion: '142'`** for all new games. (Older games pin other versions like `1006`, `0767`, `136`, `138`; the version in the `require` and in `metadata()` must always match.) `142` includes image cropping / spritesheets (§7.3.1) and shadow/glow effects (§7.4).

---

## 3. The Game class contract

Extend `Game` and implement these. Only `metadata()`, the constructor, and `getLayers()` are mandatory; the rest are optional hooks the server calls when present.

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class MyGame extends Game {
    // REQUIRED. Static. Describes the game. squishVersion must match the require above.
    static metadata() { return { squishVersion: '142', name: 'My Game' /* ... */ }; }

    // REQUIRED. Build your initial scene graph. ALWAYS call super() first.
    constructor() {
        super();
        // build this.base and children here
    }

    // REQUIRED. Return the layer list. Almost always a single root.
    getLayers() {
        return [{ root: this.base }];
    }

    // OPTIONAL HOOKS (implement the ones you need):

    // A player joined. info.name is their display name.
    handleNewPlayer({ playerId, info, settings, clientInfo }) {}

    // A player left. Clean up their nodes/state.
    handlePlayerDisconnect(playerId) {}

    // Keyboard input. key is like 'ArrowUp', 'w', 'a', ' ', 'Enter', etc.
    handleKeyDown(playerId, key) {}
    handleKeyUp(playerId, key) {}

    // Called every frame if metadata().tickRate is set. Use for game loops/physics.
    tick() {}

    // Gatekeeper for joins. Return false to refuse the player (e.g. game full).
    canAddPlayer() { return true; }

    // Called when the session ends. Base Game.close() clears tracked timers (see §10).
    // Override to also remove nodes, but you usually don't need to.
    close() { super.close?.(); }
}

module.exports = MyGame;
```

**Method signatures are exact and important:**
- `handleNewPlayer` receives a **single object** `{ playerId, info, settings, clientInfo }` — destructure it. `playerId` is a number. `info.name` is the player's name.
- `handlePlayerDisconnect(playerId)` receives the **bare id**, not an object.
- `handleKeyDown(playerId, key)` / `handleKeyUp(playerId, key)` — two positional args.
- A node's `onClick` receives `(playerId, x, y)` — see §9.

---

## 4. The single most important rule: state changes need `onStateChange()`

Node properties (`coordinates2d`, `fill`, `color`, `text`, `playerIds`, ...) are **plain fields with no setters**. Mutating them updates your data but does **not** push anything to clients. You must notify after mutating:

```js
// Move a node and recolor it:
this.player.node.coordinates2d = ShapeUtils.rectangle(newX, newY, 5, 5);
this.player.node.fill = COLORS.RED;
this.base.node.onStateChange();   // <-- REQUIRED. Without this, nothing updates on screen.
```

Rules of thumb:
- After a batch of direct property mutations, call `onStateChange()` **once** on your root node (`this.base.node.onStateChange()`).
- The convenience methods that change tree structure already notify for you: `addChild`, `addChildren`, `removeChild`, `clearChildren`, and `BaseNode.update(...)`. You do **not** need an extra `onStateChange()` after those.
- In a `tick()` loop, do all your mutations, then one `onStateChange()` at the end.

Two equivalent ways to change a node:

```js
// (a) BaseNode.update() — sets fill and/or coordinates2d AND notifies:
this.box.update({ fill: COLORS.GREEN, coordinates2d: ShapeUtils.rectangle(10, 10, 20, 20) });

// (b) Direct field mutation + explicit notify:
this.box.node.fill = COLORS.GREEN;
this.base.node.onStateChange();
```

To change text, reassign the whole `text` object (then notify):

```js
this.scoreText.node.text = { text: `Score: ${this.score}`, x: 50, y: 10, size: 3, align: 'center', color: COLORS.WHITE };
this.base.node.onStateChange();
```

### 4.1 What a notify costs — and the node-pooling rule

Every notify — an explicit `onStateChange()` **or** one fired for you by `addChild`/`removeChild`/`clearChildren` — marks the tree dirty; at the end of the current event-loop turn the server **re-squishes the ENTIRE tree and re-broadcasts it to every player**. Bursts coalesce (mutating 50 nodes in one tick still produces one squish + one broadcast), so you don't pay per call — you pay **per dirty tick, proportional to total node count × players**. Consequences, in order of how badly generated games get them wrong:

1. **Only notify when something actually changed.** An unconditional `this.base.node.onStateChange()` at the bottom of `tick()` re-squishes and re-broadcasts the whole tree `tickRate` times per second even when the game is sitting on a menu. Track a `changed` flag and notify once, only when true (see §14.2).

2. **Pool particle/trail/projectile nodes — never create/remove nodes per tick.** Per-tick `new GameNode.Shape(...)` + `addChild` + later `removeChild` churn (explosions, engine trails, bullets) grows the tree, generates garbage, and — because tree ops each mark the tree dirty — guarantees a full re-squish every single tick. It's also where orphan bugs hide (a node created but never added, or added but never removed on some code path, leaks forever). The correct pattern is a **fixed pool created once in the constructor, mutated in place, hidden when idle**:

```js
// Constructor: fixed pool, all hidden (zero-size, transparent).
this.particles = [];
for (let i = 0; i < 48; i++) {
    this.particles.push({
        active: false, x: 0, y: 0, vx: 0, vy: 0, life: 0,
        node: new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
            fill: [0, 0, 0, 0],
            color: [255, 255, 255, 255]
        })
    });
    this.base.addChild(this.particles[i].node);
}

// Emit: claim inactive slots (if none are free, just emit fewer — the pool is the budget).
emitBurst(x, y, fill, count) {
    for (const p of this.particles) {
        if (count <= 0) break;
        if (p.active) continue;
        count--;
        p.active = true; p.life = 20; p.x = x; p.y = y;
        /* set vx/vy */ p.node.node.fill = fill;
    }
}

// tick(): mutate in place; on death hide, don't remove. Fade via `color` alpha (§7.4).
for (const p of this.particles) {
    if (!p.active) continue;
    p.x += p.vx; p.y += p.vy; p.life--;
    if (p.life <= 0) {
        p.active = false;
        p.node.node.coordinates2d = ShapeUtils.rectangle(0, 0, 0, 0);
        p.node.node.fill = [0, 0, 0, 0];
        continue;
    }
    p.node.node.coordinates2d = ShapeUtils.rectangle(p.x, p.y, 0.6, 0.6);
    p.node.node.color = [255, 255, 255, Math.round(255 * p.life / 20)];
}
// ... then ONE onStateChange() for the whole tick.
```

   The same applies to enemies and pickups in wave games: cap the population, reuse dead slots. `addChild`/`removeChild` is for structural moments (screen transitions, players joining/leaving), not for the per-frame lifecycle of effects.

3. **Update `Text` by reassigning `node.text` — never remove-and-recreate the text node** to change a score/label. Recreation is churn, and it reorders the node's draw position in the tree.

4. **Budget node count and glow.** Total bandwidth ≈ node count × ~55 bytes × tickRate × players — keep the tree in the low hundreds of nodes. And the client renders `effects.shadow` with canvas `shadowBlur`, one of the most expensive canvas operations: glow a **handful of focal nodes** (title, the player's ship, a boss), not every enemy, particle, and pickup, or client framerate dies even when the server is fine.

---

## 5. `metadata()` reference

```js
static metadata() {
    return {
        squishVersion: '142',          // REQUIRED. Must match require('squish-142').
        name: 'Hot Potato',            // Display name.
        author: 'Your Name',           // Creator.
        description: 'One-line pitch shown in the catalog.',
        aspectRatio: { x: 16, y: 9 },  // Display aspect ratio. Common: {16,9}, {4,3}, {1,1}.
        thumbnail: 'asset-id-hash',     // Optional asset id used as the catalog thumbnail.
        tickRate: 60,                   // Frames/sec for tick(). Omit if you have no game loop.
        assets: {                       // Optional. Images/audio/fonts (see §11).
            'potato': new Asset({ id: '48685183f94c7a3c14f315444c6460bd', type: 'image' })
        }
    };
}
```

- The plane is always `0–100`; `aspectRatio` only controls how that square is presented (letterboxing on the client). Build your layout in `0–100` space and pick an aspect ratio that suits it.
- **Aspect-ratio distortion gotcha:** because the `0–100` square is stretched to fill the aspect rectangle, an x-unit and a y-unit are **not** the same size on screen unless the ratio is `{1,1}`. At `{16,9}` everything is wider than tall — a "square" looks like a rectangle, a `polyCircle` looks like an ellipse, and a 45° heading doesn't look like 45°. For UI/party games this is fine. For **rotation- or distance-based geometry** (twin-stick shooters, anything with circles, orbits, or true angles), prefer **`aspectRatio: { x: 1, y: 1 }`** so the math matches the pixels, or compensate for the ratio in your trig. To draw a **physically square** rect at ratio `{x, y}`, use `height = width * (x / y)` (e.g. at `{16,9}` a `2 × 3.56` rect renders square; at `{9,16}` use `2 × 1.13`).
- **Text size is relative to canvas WIDTH only.** A `size: s` line of text is `s%` of the canvas width tall in pixels — which is `s * (aspectX / aspectY)` **y-units** tall on the plane. At `{1,1}` a size-2 text is ~2 y-units tall; at `{16,9}` it's ~3.6; at `{9,16}` it's ~1.1. Use this to vertically center a label in a box: `textY = boxY + (boxH - size * aspectX / aspectY) / 2`. **Text width is NOT knowable server-side**: each client's canvas resolves `monospace` to its own font, with advance widths anywhere from ~0.6 to ~0.85 of the font size. Budget wide (~`0.85 * size` x-units per character) when sizing boxes/wrapping so wide fonts don't overflow, and never position anything by summing character widths — to place a cursor or caret, embed it in the string itself (a `'▌'` glyph appended to the text lands exactly after the last character on every client; see the Typewriter game).
- `tickRate` is frames per second for `tick()`. **Every tick with a state change re-squishes and re-broadcasts the whole tree**, so high rates cost real bandwidth. In practice: **15–30 for action games** (shipped catalog games use 15–20 and feel snappy), **8–15 for casual/UI-driven games**, omit entirely for purely event-driven games (click/turn-based) that update only in handlers. Express all in-game durations as `seconds * TICK_RATE` so pacing tweaks don't silently change timers.

---

## 6. Coordinates and colors

**Coordinates** are `[x, y]` pairs in `0–100` space. A shape's `coordinates2d` is an array of vertices. Build rectangles and triangles with `ShapeUtils`:

```js
ShapeUtils.rectangle(x, y, width, height)
// returns [[x,y],[x+w,y],[x+w,y+h],[x,y+h],[x,y]]  (top-left origin, closed loop)

ShapeUtils.triangle(x1, y1, x2, y2, x3, y3)
// returns [[x1,y1],[x2,y2],[x3,y3],[x1,y1]]
```

You can also pass a raw vertex array for arbitrary polygons: `coordinates2d: [[10,10],[90,10],[50,90],[10,10]]`.

**Reading a rectangle's position/size back** (common in physics/collision code):

```js
const x = node.node.coordinates2d[0][0];
const y = node.node.coordinates2d[0][1];
const w = node.node.coordinates2d[1][0] - x;
const h = node.node.coordinates2d[2][1] - y;
```

> **Precision gotcha:** coordinates are serialized as an integer + a 2-decimal fraction, so the on-screen resolution is **~0.01 units** in `0–100` space. Movement smaller than that per frame rounds away — a `tick()` that adds `0.005` to a position will visually stutter or not move at all. Keep per-frame deltas ≥ ~0.05, or accumulate sub-unit motion in a plain variable and only write the rounded value into `coordinates2d`.

> **Off-plane / negative coordinates:** every coordinate is clamped to `[0, 255]` at serialization. **Negative values pin to `0`** — there is no "just off-screen" above or to the left. An enemy spawned at `y = -2` renders sitting *on* the top edge, not hidden beyond it. Values `100–255` survive, so sliding off the **right/bottom** works. To make something enter from the left or top, spawn it at the edge (`0`) already moving inward, or keep its position in plain variables and only give it a node once it's on the plane.

> **Vertex-count cap:** a node's `coordinates2d` is serialized into a length-limited wire frame — **at most ~126 vertices per node**. Beyond that the frame overflows and the node breaks. For detailed silhouettes (terrain skylines, rings, long strips) budget vertices: e.g. a destructible terrain polygon works at 96 columns (~100 vertices), and a "thick outline" strip that traces a path top-and-bottom doubles its vertex count — sample every other point to stay under the cap. Split very detailed geometry across multiple nodes.

**Colors** are `[r, g, b, a]` arrays, each `0–255`. `a` (alpha) of `0` is fully transparent, `255` fully opaque.

> **Color channels must be integers `0–255` — out-of-range values WRAP, they don't clamp.** Channels are written raw into the frame's byte buffer, so a computed value like `alpha: life * 8` that reaches `400` wraps to `144` mid-fade (the fade visibly flickers back on), and negatives wrap high. Clamp anything you compute: `Math.max(0, Math.min(255, Math.round(v)))`.

```js
const { COLORS } = Colors;
COLORS.RED;            // [255, 0, 0, 255]
COLORS.HG_BLUE;        // [148, 210, 230, 255]  (Homegames brand blue)
[0, 0, 0, 0];          // transparent (useful for invisible click targets / hit boxes)
Colors.randomColor();  // a random named color
Colors.randomColor(['BLACK', 'WHITE', 'ALMOST_BLACK']); // random, excluding by NAME
```

> **`randomColor` excludes by color NAME (string), not by value.** The exclusion list is matched against palette key names like `'BLACK'`/`'HG_BLUE'`, **not** color arrays — `Colors.randomColor([COLORS.BLACK])` silently excludes nothing (you passed an array, not the name). To keep, say, ships off a dark background, pass the names: `Colors.randomColor(['BLACK','ALMOST_BLACK','HG_BLACK','CHARCOAL'])`.

The complete named palette — these are the ONLY valid `COLORS.*` names:

```
ALMOST_BLACK, ALMOST_WHITE, ANTIQUE_WHITE, AQUA, AQUAMARINE, BEIGE, BIG_GRAY, BLACK, BLAY, BLUE,
BLUE_WHISPER, BLEEN, BLOOD, BOOGER, BRIGHT_GRAY, BRONZE, BROWN, CANDY_GREEN, CANDY_PINK, CANDY_RED,
CHARCOAL, CALM_BLUE, COOL_BLUE, COOL_GREEN, CORAL, CORPORATE_BEIGE, CREAM, CREAMSICLE, CYAN,
DARK_TURQUOISE, DEEP_BLUE, DEEP_PURPLE, DEEP_RED, DIM_GRAY, DULL_BLUE, EMERALD, EVERGREEN,
FRIENDLY_BLUE, FUCHSIA, FUNNY_PURPLE, GOLD, GOLDMEMBER, GRAY, GREEN, GUN_METAL_GRAY, HARD_ORANGE_RED,
HARD_PINK, HG_BLACK, HG_BLUE, HG_RED, HG_YELLOW, INTERIOR_RED, INVITATION_BLUE, KHAKI, LAVENDER,
LIGHT_CORAL, LIGHT_SEA_GREEN, NAVY, MAGENTA, MAROON, MEAN_SEA, MERLOT, MINT, MUSTARD, NEON_BOOGER,
NEON_PINK, ORANGE, ORANGE_RED, PALE_TURQUOISE, PEACH, PERFUME_PINK, PERRYWINKLE, PINK, POWDER_BLUE,
PURPLE, REAL_ESTATE_BLUE, RED, RUST, SALMON, SEA_GREEN, SHARP_YELLOW, SILVER, SIMPLE_GRAY,
SLEEPY_PINK, SMOKE, SMOOTH_BLUE, SOFT_GREEN, SOFT_MINT, SOFT_PINK, STRESSED_PURPLE, SKY_BLUE,
STANDARD_GRAY, STORM_GRAY, SUCCESS_GREEN, TEAL, TENSE_SKY, TERRACOTTA, THICK_LUXURY, TURQUOISE,
WALLPAPER_BEIGE, WALLPAPER_GREEN, WHITE, YELLOW
```

> **An invented color name fails SILENTLY as an invisible shape.** `COLORS.CHOCOLATE` or `COLORS.DARK_SAGE` isn't an error — it's `undefined`, and undefined fields are skipped at serialization, so the node renders with **no fill at all**. A "background that doesn't show up" or "shape that never appears" is very often a made-up palette name. If the exact color you want isn't in the list above, use an explicit `[r,g,b,a]` array (e.g. chocolate ≈ `[123, 63, 0, 255]`).

---

## 7. Node types

There are exactly three, all created via `GameNode`. All accept an optional numeric `id`, `playerIds`, and (for visible nodes) `onClick`, `onHover`, `offHover`.

### 7.1 `GameNode.Shape` — polygons, rectangles, lines

```js
const box = new GameNode.Shape({
    shapeType: Shapes.POLYGON,                      // POLYGON | LINE  (do NOT use CIRCLE)
    coordinates2d: ShapeUtils.rectangle(10, 10, 30, 20),
    fill: COLORS.CORAL,                             // interior color (RGBA). PREFER fill.
    color: [0, 0, 0, 255],                          // STROKE color — required if you set border
    border: 6,                                       // optional outline WIDTH (a number, see below)
    onClick: (playerId, x, y) => { /* ... */ },     // optional; makes it interactive
    effects: { shadow: { color: [0,255,255,255], blur: 12 } },  // optional neon glow (§7.4)
    playerIds: [42]                                  // omit entirely for visible-to-everyone. See §8.
});
```

- `shapeType` comes from `Shapes`: `Shapes.POLYGON` (the workhorse) or `Shapes.LINE`.
- **`Shapes.CIRCLE` exists as a constant but is NOT rendered — do not use it.** Approximate a circle with a many-sided polygon (see the helper below).
- **Use `fill` for the shape's interior color.** `color` is the **stroke** color, used together with `border`.
- **`border` is a single NUMBER, not an object.** It's an outline width on a `0–255` scale (the client renders it as `(border/255) * 0.1 * canvasWidth`, so small numbers like `2`–`10` are thin lines). The stroke is drawn in the node's **`color`** field — so **if you set `border` you must also set `color`**, or rendering the stroke will fail. There is **no `border.color`/`border.width` object** — `border: { color, width }` squishes to garbage. Outlined shape = `fill` (interior) + `color` (stroke) + `border` (numeric width).
- Rectangles and arbitrary polygons via `POLYGON` cover ~95% of needs. `coordinates2d` is just a vertex list, so you can build **any polygon and rotate it with plain trig** — e.g. a ship triangle that points along an angle, or a round shape:

```js
// A round-ish polygon (since CIRCLE doesn't render). sides ~16 looks smooth.
const polyCircle = (cx, cy, r, sides = 16) => {
    const pts = [];
    for (let i = 0; i <= sides; i++) {
        const a = (i / sides) * Math.PI * 2;
        pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r]);
    }
    return pts;   // closed loop (last point == first)
};
// A triangle rotated to face `angle` (radians), centered at (x,y):
const facing = (x, y, angle, size) => ShapeUtils.triangle(
    x + Math.cos(angle) * size,        y + Math.sin(angle) * size,
    x + Math.cos(angle + 2.6) * size,  y + Math.sin(angle + 2.6) * size,
    x + Math.cos(angle - 2.6) * size,  y + Math.sin(angle - 2.6) * size,
);
// A thick line / "stick" from (x1,y1) to (x2,y2) as a 4-corner polygon
// (paddles, chopsticks, laser beams, limbs — anything long and rotatable):
const thickLine = (x1, y1, x2, y2, width) => {
    const a = Math.atan2(y2 - y1, x2 - x1);
    const dx = Math.sin(a) * width / 2, dy = Math.cos(a) * width / 2;
    return [[x1 - dx, y1 + dy], [x2 - dx, y2 + dy], [x2 + dx, y2 - dy], [x1 + dx, y1 - dy], [x1 - dx, y1 + dy]];
};
```

> When a game has **mirrored geometry** (a left and a right of anything), compute it with ONE helper like the above called twice with mirrored arguments — never as two copy-pasted trig blocks. See §15.1 for why this rule exists.

- Transparent fill `[0,0,0,0]` + an `onClick` makes an invisible hit-box / button overlay (but see §9's hit-test rules — an invisible node still swallows clicks for things drawn beneath it). To **temporarily hide a node without removing it**, either set `fill` to `[0,0,0,0]` or set `playerIds = [0]` (visible to nobody — see §8); restore later.
- A `Shape` can also carry an `input` field (to act as an on-screen text box) and `onHover`/`offHover` callbacks — see §9.

### 7.2 `GameNode.Text`

```js
const label = new GameNode.Text({
    textInfo: {
        text: 'Hello',
        x: 50, y: 20,        // anchor position in 0–100 space
        size: 2,             // relative font size (1 ≈ small, 3 ≈ large heading)
        align: 'center',     // 'left' | 'center' | 'right'
        color: COLORS.WHITE,
        font: 'default'      // optional
    }
});
```

Note the field is `textInfo` in the constructor, but it is stored on the node as `node.text` (so you update it via `label.node.text = {...}`, see §4).

> **No newlines, no wrapping.** The client draws each `Text` node with a single canvas `fillText` call: a `'\n'` in the string does NOT line-break (the whole thing renders as one line), and long text never wraps on its own. For multi-line text (instructions, "GAME OVER\nFinal Score" screens), create **one `Text` node per line** and space them vertically — line height in y-units is `size * (aspectX / aspectY)` (§5), so at `{16,9}` size-2.5 lines sit nicely ~5 y-units apart.

> **Text nodes are NOT clickable.** Unlike `Shape` and `Asset`, the `Text` constructor only accepts `{ textInfo, playerIds, input, node, id }` — there is **no `onClick`, `onHover`, or `offHover`**. Passing an `onClick` to a `Text` node does nothing; it is silently dropped and the text will never respond to taps. **To make a clickable text label / "button", put the click handler on a `Shape` and render the `Text` on top of it** — see §7.2.1.

#### 7.2.1 Text is not a button — build buttons from a Shape + Text

There is no button node and text cannot receive clicks. A "button" is just a **clickable `Shape` polygon with a `Text` node positioned on top of it**. The `Shape` carries the `onClick` and the visible background; the `Text` carries the label and must be drawn *after* (or as a sibling added after) the shape so it sits on top. Size the shape — not the text — to define the tap target, and center the text over it.

```js
// Reusable helper: a rectangular button at (x,y) sized (w,h) with a centered label.
makeButton({ x, y, w, h, label, fill, onClick }) {
    const bg = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(x, y, w, h),
        fill,
        onClick   // the SHAPE is what's clickable
    });
    const text = new GameNode.Text({
        textInfo: {
            text: label,
            x: x + w / 2,        // horizontal center of the shape
            y: y + h / 2 - 1.5,  // nudge up so the text baseline looks vertically centered
            size: 2,
            align: 'center',     // pairs with x being the center
            color: COLORS.WHITE
        }
        // NO onClick here — it would be ignored. The bg shape handles the tap.
    });
    bg.addChild(text);           // text rides along as a child of the button background
    return bg;
}

// usage:
const startBtn = this.makeButton({
    x: 35, y: 45, w: 30, h: 12, label: 'Start', fill: COLORS.GREEN,
    onClick: (playerId, x, y) => this.startGame(playerId)
});
this.base.addChild(startBtn);
```

Notes:
- The text's `x`/`y` are independent plane coordinates, **not** relative to the parent shape — compute them from the shape's position (`x + w/2`, etc.). Adding the text as a child of the shape only affects render order and tree cleanup, not positioning.
- Because the text is a child of the button shape, removing the button (`removeChild(bg.id)`) removes the label with it.
- The whole shape is the hit target, so the player can tap anywhere on the button — including directly on the letters — and the shape's `onClick` fires. The text being non-interactive doesn't create a "dead zone".
- For an invisible text-over-image button, use the same pattern with a transparent fill `[0,0,0,0]` or an `Asset` node as the background.

### 7.3 `GameNode.Asset` — images and audio

```js
const sprite = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(25, 25, 50, 50),  // clickable bounds of the node
    assetInfo: {
        'potato': {                       // KEY must match a key in metadata().assets
            pos:  { x: 30, y: 35 },       // where the image's top-left sits, 0–100 space
            size: { x: 40, y: 30 }        // image width/height, 0–100 space
        }
    },
    playerIds: [0]
});
```

Audio is also an `Asset` node — give it zero size and a `startTime` (seconds into the clip):

```js
const sound = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
    assetInfo: {
        'hiss': { pos: { x: 0, y: 0 }, size: { x: 0, y: 0 }, startTime: 0 }
    }
});
// Add it to the tree to play; remove it to stop:
this.base.addChild(sound);
this.setTimeout(() => this.base.removeChild(sound.id), 250);
```

The `assetInfo` key (`'potato'`, `'hiss'`) is a **reference to `metadata().assets`** — you do not embed image/audio bytes in the game; you reference them by the asset id declared in metadata.

### 7.3.1 Cropping an image / spritesheets (`squish-140`+)

An image `Asset` can show just a **rectangular sub-region** of its source image instead of the whole thing, via four optional fields inside `assetInfo[key]`:

```js
const tile = new GameNode.Asset({
    coordinates2d: ShapeUtils.rectangle(10, 10, 10, 10),
    assetInfo: {
        'sheet': {
            pos:  { x: 10, y: 10 },
            size: { x: 10, y: 10 },
            // Crop: percentage (0–100) of the SOURCE image to cut off EACH edge.
            cropLeft: 0, cropTop: 0, cropRight: 50, cropBottom: 50   // show the top-left quarter
        }
    }
});
```

- The crop fields are an **inset per edge, in percent of the source image** — `cropLeft: 25` drops the left 25% of the image, `cropRight: 25` drops the right 25%, etc. All default to `0` (whole image).
- The surviving sub-region is then **stretched to fill `pos`/`size`** (no automatic aspect-ratio preservation) — so pick a `size` whose aspect matches the cropped region if you don't want distortion.
- `cropLeft + cropRight` (and `cropTop + cropBottom`) must be `< 100`; an inset that collapses the region is ignored and the full image is drawn.

This unlocks **spritesheets and tilemaps from a single asset** — pack many frames/tiles into one image and crop to the one you want. To select frame `(col, row)` from a `cols × rows` grid:

```js
const frameCrop = (col, row, cols, rows) => ({
    cropLeft:   (col / cols) * 100,
    cropRight:  ((cols - 1 - col) / cols) * 100,
    cropTop:    (row / rows) * 100,
    cropBottom: ((rows - 1 - row) / rows) * 100,
});
// animate by reassigning assetInfo each tick:
this.sprite.node.asset = { 'sheet': { pos, size, ...frameCrop(this.frame, this.facing, 8, 4) } };
this.base.node.onStateChange();
```

> **Version gate:** cropping requires **`squish-140` or newer** — included in the default `142`. On `138`/`139` the crop fields are silently ignored (the image renders whole, no error).

### 7.4 Effects (glow) and transparency — the rules that actually work

**Glow / shadow.** `Shape` and `Asset` nodes accept an `effects` field; the only supported effect is a drop shadow, which doubles as a **neon glow** — the signature look of the first-party catalog:

```js
const glow = (color, blur) => ({ shadow: { color: [color[0], color[1], color[2], 255], blur } });

new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(40, 40, 20, 20),
    fill: [0, 255, 255, 255],
    effects: glow([0, 255, 255, 255], 14)   // cyan glow, blur 14
});
```

- `blur` is a number (canvas `shadowBlur` pixels); `6–12` is a subtle glow, `16–30` dramatic, `40` an explosion flash.
- To remove an effect, set `node.node.effects = null` (never `{}` — an empty object crashes serialization).
- **`Text` nodes do NOT accept `effects`.** To give a title/banner a glow, fake it with **4 dim offset copies under a bright core** — the standard pattern:

```js
makeGlowText(text, x, y, size, color, glowColor, playerIds) {
    const gc = glowColor || color;
    const offsets = [[-0.25, 0], [0.25, 0], [0, -0.25], [0, 0.25]];
    const nodes = offsets.map(o => new GameNode.Text({
        textInfo: { x: x + o[0], y: y + o[1], text, size, align: 'center', font: 'monospace', color: [gc[0], gc[1], gc[2], 140] },
        playerIds
    }));
    nodes.push(new GameNode.Text({ textInfo: { x, y, text, size, align: 'center', font: 'monospace', color }, playerIds }));
    return nodes;   // add all to the tree; the bright core is last so it draws on top
}
```

**Transparency and fading — `fill` alpha is nearly binary; real fades use `color` alpha.** The client renders `fill`'s alpha byte through CSS, which clamps it: `fill[3] = 0` is invisible, but **any `fill[3] ≥ 1` renders essentially opaque** — you cannot fade a shape by animating `fill` alpha. What actually fades a node is the **`color` field's alpha**, which drives the canvas global alpha for that node:

```js
// Fade a node out over time (e.g. a particle or a "derez" trail):
node.node.color = [r, g, b, Math.round(255 * lifeRemaining / lifeTotal)];
this.base.node.onStateChange();
```

Caveats:
- The global alpha is only reset by the **next node that has a `color`** — a faded node can "leak" its transparency onto later-drawn shapes that lack one. Rule: **when you fade anything, give every visible `Shape` an explicit `color`** (use `[255,255,255,255]` when you don't need a stroke).
- Glow persists at full strength while a node fades via `color` alpha; set `effects = null` when starting a fade-out.

---

## 8. Player visibility model (`playerIds`)

Every node has `playerIds`, an array controlling who sees it. **Get these semantics right — they are commonly stated backwards:**

- `[]` (empty — the default when you omit `playerIds`) → **visible to all players.**
- `[42]` → visible only to player `42`.
- `[42, 99]` → visible to players `42` and `99`.
- `[0]` → **visible to NOBODY** (player ids start at 1, so scoping to `0` hides the node from everyone). This is the standard trick for hiding a node without removing it — e.g. a JOIN button once everyone has joined.

> **`playerIds` is VISIBILITY, not ownership — do NOT tag gameplay entities with their controller's id.** The most common generated-game bug: giving each player's ship/avatar `playerIds: [playerId]` "because it's theirs". That **hides every ship from every other player** — in multiplayer everyone sees an empty arena with enemies chasing invisible targets. Nodes need no player tag to be controlled by a player; input is already routed per player via the `playerId` argument to `handleKeyDown`/`onClick`. Leave shared-world entities (avatars, ships, bullets, enemies, pickups) **unscoped** (omit `playerIds` entirely), and scope only genuinely private UI: a hand of cards, a personal HUD, a "YOU" marker.
>
> Relatedly: **player ids are the numbers the server hands you** in `handleNewPlayer`/input handlers. Never invent or renumber them (e.g. `Object.keys(this.players).indexOf(id) + 1`) — ids are not dense, don't start at your join order, and a derived id scopes the node to the wrong player or to nobody.

Scoping applies to the **whole subtree**: children of a scoped node are only sent to that node's players (a child can narrow the set further with its own `playerIds`, but not widen it). For a scoped button, it's still good practice to set the same `playerIds` on both the shape and its label. Clicks respect scoping too — a node scoped away from a player can't be clicked by them (§9).

This is how you build per-player UI (private hands, individual HUDs, "your turn" prompts) in a single shared game. Helpers on every node:

```js
node.showFor(playerId);   // add a player to the visibility set (and drop a hiding 0)
node.hideFor(playerId);   // remove a player; if none left, sets [0] (hidden from everyone)
// or set directly, then notify:
node.node.playerIds = [playerId];
this.base.node.onStateChange();
```

> **Privacy caveat (secrets games, frameless sessions):** the server builds a filtered frame only for players who appear in **at least one node's `playerIds`**. A connected player with **zero** nodes scoped to them falls back to the raw unfiltered state — i.e. **they receive everyone's "private" nodes**. In framed sessions the platform chrome scopes nodes per player, masking this; in frameless sessions (studio / direct play flows) it's live. If your game has real secrets (hidden words, private hands), give **every connected player** a persistent scoped node in `handleNewPlayer` — a zero-size invisible "privacy anchor" is enough:
>
> ```js
> handleNewPlayer({ playerId }) {
>     const anchor = new GameNode.Shape({
>         shapeType: Shapes.POLYGON,
>         coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0),
>         playerIds: [playerId]
>     });
>     this.anchors[playerId] = anchor;
>     this.base.addChild(anchor);
>     // remove it in handlePlayerDisconnect
> }
> ```

> **Frameless identity:** don't rely on the platform frame to tell players who they are — frameless sessions have no chrome, and `info.name` can be absent (fall back to `'PLAYER ' + playerId`). Wherever the game shows a roster (lobby list, scoreboard, turn order), add a small **"YOU" marker scoped to each player** next to their own entry, and when a player is assigned a color/avatar, show them a scoped "YOU ARE THE CYAN SHIELD"-style banner.

Example — give each player their own colored marker only they can see:

```js
handleNewPlayer({ playerId }) {
    const marker = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(45, 90, 10, 5),
        fill: Colors.randomColor(),
        playerIds: [playerId]   // only this player sees it
    });
    this.players[playerId] = marker;
    this.base.addChild(marker);
}
```

---

## 9. Input

### Clicks / taps
Attach `onClick` to a **`Shape` or `Asset`** node (the only node types that accept it — **`Text` does not**, see §7.2). Signature: **`(playerId, x, y)`** — the clicking player's id, and the click position in `0–100` plane space. To make a clickable label, put the `onClick` on a `Shape` and lay a `Text` node on top of it (§7.2.1).

```js
const button = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(40, 40, 20, 20),
    fill: COLORS.GREEN,
    onClick: (playerId, x, y) => {
        // Only the owner may press their button:
        if (Number(playerId) === Number(this.ownerId)) this.doThing();
    }
});
```

Clicks and taps are unified — `onClick` fires for both mouse and touch. Make tap targets generously sized for mobile.

#### 9.1 Click routing: the topmost node wins, clickable or not

The server resolves a click to the **topmost node whose polygon contains the point** — draw order (parent before children, siblings in insertion order; later = on top). Crucially, **it does not skip non-clickable nodes**: if the topmost containing node has no `onClick`, the click is **silently dropped** — it does not fall through to a clickable node underneath. Two consequences:

1. **Container/layer nodes must be zero-size.** The common pattern of grouping nodes under invisible full-screen `Shape` "layers" (HUD layer, particle layer, overlay) will **swallow every click on anything drawn beneath them** if those containers are `rectangle(0, 0, 100, 100)`. Make containers `rectangle(0, 0, 0, 0)` — children render and receive clicks normally, and the container itself can never intercept a click:

```js
makeContainer() {
    return new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 0, 0)   // zero-size: never swallows clicks
    });
}
```

2. **Full-screen tap steering needs a dedicated tap-catcher.** Putting `onClick` on your background/root doesn't work once anything is drawn over it — taps land on trails, enemies, terrain, etc. and die there. Instead add a transparent full-screen `Shape` **above the playfield but below the UI buttons**, and put the tap handler on it (buttons must be later siblings so they still win):

```js
this.tapCatcher = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),   // no fill -> invisible, still clickable
    onClick: (playerId, x, y) => this.handleTap(playerId, x, y)
});
// draw order: playfield layers, THEN tapCatcher, THEN hud/overlay (buttons)
this.base.addChildren(this.trailLayer, this.particleLayer, this.tapCatcher, this.hud, this.overlay);
```

Also: `playerIds` scoping applies to clicks (a node hidden from a player can't be clicked by them — this is how per-player buttons work), and `Text` nodes never intercept clicks (no `coordinates2d`), so a button's label can't create a dead zone.

### Keyboard
Implement `handleKeyDown(playerId, key)` / `handleKeyUp(playerId, key)`. `key` is the standard browser key string: `'ArrowUp'`, `'ArrowDown'`, `'ArrowLeft'`, `'ArrowRight'`, `'w'`, `'a'`, `'s'`, `'d'`, `' '` (space), `'Enter'`, single characters, etc. The client forwards printable characters (`' '`–`'z'`, including capitals and digits), the arrow keys, `Backspace`, `Enter`, and `Meta` — nothing else. Support both arrows and WASD for movement.

**How held keys actually arrive:** the client sends one `keydown` on the physical press, then **re-sends `keydown` every ~33ms while the key is held — with NO initial delay** — and sends a debounced `keyup` on release. This is ideal for movement (hold-to-move just works) and catastrophic for typing: a normal ~100ms keystroke delivers 3–4 duplicate `keydown`s, so naive `buffer += key` types `"hhhh"`.

#### Live typing (a text editor that feels like a document)

`input: { type: 'text' }` (below) opens a **modal prompt** — fine for one-shot entry (a name, a guess), wrong for live typing. For text that appears on screen as the player types, build on raw `handleKeyDown` and reconstruct real keyboard feel by gating the 33ms re-sends like an OS keyboard: a key not seen recently is a fresh press (types instantly); while held, the re-sends are a *hold heartbeat* that only types after an initial delay, then at a fast repeat rate. This also makes held-Backspace erase properly.

```js
// per player: writer.keys = {}
handleKeyDown(playerId, key) {
    if (key !== 'Backspace' && key !== 'Enter' && key.length !== 1) return;
    const now = Date.now();
    const state = this.writers[playerId].keys[key];

    if (!state || now - state.lastSeen > 400) {          // fresh physical press
        this.writers[playerId].keys[key] = { lastSeen: now, repeatAt: now + 450 };
        this.applyKey(playerId, key);                     // type it IMMEDIATELY
        return;
    }
    state.lastSeen = now;                                 // held: heartbeat
    if (now >= state.repeatAt) {                          // repeat after 450ms,
        state.repeatAt = now + 55;                        // then ~18 chars/sec
        this.applyKey(playerId, key);
    }
}
handleKeyUp(playerId, key) { delete this.writers[playerId].keys[key]; }
// applyKey: append / Backspace-slice / '\n' on Enter, re-render the text
// nodes, then onStateChange() — mutate in the handler, not in tick(), so
// letters land on screen with zero added latency.
```

The 400ms staleness check doubles as a safety net: if a `keyup` is ever lost, the key un-sticks by itself. See `src/games/text-input` (Typewriter) in homegames-core for the complete pattern with wrapping, a blinking cursor, and a tap-to-type prompt fallback for phones.

> Mobile players have no physical keyboard. If your game needs keyboard control, also provide on-screen `onClick` buttons (or the `input:{type:'text'}` prompt for text), or design click/tap-first.

### Text input (on-screen fields)

Besides clicks and keyboard there is a third input path: a node can present an **editable text field** via an `input` property. It is accepted on **`Shape` and `Text`** nodes (not `Asset`). The client renders an input box over the node's bounds; as the player edits it, the server calls your `oninput(playerId, value)` with the field's current contents:

```js
const searchBox = new GameNode.Shape({
    shapeType: Shapes.POLYGON,
    coordinates2d: ShapeUtils.rectangle(20, 5, 60, 10),
    fill: COLORS.WHITE,
    input: {
        type: 'text',
        oninput: (playerId, value) => {
            this.query = value;             // `value` is the full current text, not one keystroke
            this.runSearch(playerId);       // mutate state, then onStateChange()
        }
    }
});
```

- `oninput` fires on change; treat `value` as the field's entire current string.
- This is exactly the mechanism the Homegames dashboard's own search box uses, so it is the same well-trodden path the platform relies on.
- Scope the field with `playerIds` (§8) so only the intended player sees and edits it — `input` is per node, but visibility still follows `playerIds`.
- There is also `type: 'file'` for uploads (images and audio). Its handler is `oninput(playerId, bytes, meta)`: `bytes` is a plain array of byte values (0–255), and `meta` is `{ kind, contentType, fileName }` where `kind` is `'image'`, `'audio'`, or `null` (sniffed server-side from the file's magic bytes — trust it over `contentType`, which is client-reported). Uploads are capped at 5 MB. To use an upload, wrap the bytes in an `Asset` typed by `meta.kind` and register it via the `addAsset` constructor option, then reference it from a `GameNode.Asset` as usual (audio plays while its node is in the tree):

```js
constructor({ addAsset }) {
    super();
    this.addAsset = addAsset;
    // ...
    input: {
        type: 'file',
        oninput: (playerId, bytes, meta) => {
            if (!meta.kind) return;   // not a recognized image/audio file
            const key = `upload-${meta.kind}-${++this.uploadCount}`;
            this.addAsset(key, new Asset({ id: key, type: meta.kind }, bytes)).then(() => {
                // now reference `key` from a GameNode.Asset (see §7.3)
            });
        }
    }
}
```
  See `src/games/input-test` in homegames-core for a complete image + audio upload example (including replaying an uploaded sound).

### Hover

`Shape` and `Asset` nodes also accept `onHover(playerId)` and `offHover(playerId)` (pointer enter / leave). Use them only for cosmetic affordances — **touch devices have no hover**, so never gate a mechanic on it.

---

## 10. Timing and game loop

> **`tick()` starts at construction and never pauses.** The server starts the tick interval the moment your game is instantiated — before any player joins, before any "start" button is pressed, and it keeps firing on menus and game-over screens. Two consequences:
> 1. **Gate the game loop on a phase.** Without an early `if (this.phase !== 'playing') return;`, enemies spawn, waves advance, and power-ups accumulate behind your start screen.
> 2. **Never let `tick()` touch a node a later phase creates.** `this.scoreText.node.text = ...` in `tick()` when `scoreText` is only built inside `startGame()` throws `TypeError` on a lobby that sits idle — and a throw in `tick()` crashes the session (auto-reject per §2). Create every node `tick()` references in the constructor, or guard each access.

- Set `metadata().tickRate` (FPS) and implement `tick()` for continuous simulation (movement, physics, timers counting down). Do mutations in `tick()` and end with one `onStateChange()` — **only when something changed** (§4.1).
- For delayed / repeating logic, **use the tracked timer helpers from the base `Game` class**, not the globals — they are auto-cleared when the session closes, preventing leaks:

```js
this.setTimeout(() => this.explode(), 5000);          // tracked
this.setInterval(() => this.spawnEnemy(), 1000);      // tracked
```

`Game.close()` clears all timers created via `this.setInterval` / `this.setTimeout`. If you use the global `setTimeout`/`setInterval`, you are responsible for clearing them yourself in `close()`.

**Idiom — prefer a tick counter over timers for cooldowns/durations in tick-driven games.** When you already have a `tick()` loop, the cleanest way to do fire cooldowns, respawn delays, spawn protection, etc. is to keep an incrementing tick count and compare against it — it's deterministic, needs no cleanup, and can't leak:

```js
constructor() { super(); this._t = 0; /* ... */ }
tick() {
    this._t++;
    // fire on a cooldown:
    if (firePressed && this._t >= player.fireReady) { this.fire(player); player.fireReady = this._t + 16; }
    // respawn after ~2.5s (at tickRate 60):
    if (!player.alive && this._t >= player.respawnAt) this.respawn(player);
    // ... mutate, then ONE onStateChange() ...
    this.base.node.onStateChange();
}
```

---

## 11. Assets (images, audio, fonts)

1. Declare them in `metadata().assets`, keyed by a short name, each an `Asset` instance with an `id` (the asset's hash in the Homegames asset store) and `type`:

```js
const { Asset } = require('squish-142');
// ...
assets: {
    'hero':   new Asset({ id: 'c0ffee...hash', type: 'image' }),
    'jump':   new Asset({ id: 'deadbe...hash', type: 'audio' }),
}
```

2. Reference them by key in `GameNode.Asset` `assetInfo` (see §7.3). Images use real `size`; audio uses zero size + `startTime`.
3. `type` is `'image'`, `'audio'`, or `'font'`. Keep total size within the limits in §2.

> When generating a game from scratch with no real asset ids available, prefer **drawing with shapes and text** rather than inventing fake asset ids (a fake id will load nothing). Only use `Asset` nodes when you have, or are given, valid asset ids.

---

## 12. Utilities

- `ShapeUtils.rectangle(x,y,w,h)`, `ShapeUtils.triangle(...)` — vertex builders (§6).
- `Colors.COLORS.*`, `Colors.randomColor(exclusions?)` — palette (§6).
- `GeometryUtils.checkCollisions(root, node, filter?)` — returns nodes under `root` that overlap `node` (axis-aligned rectangle test). Optional `filter(node) => boolean` to limit candidates. Useful but simple; many games hand-roll AABB checks for control (see §14).
- `ViewUtils.getView(plane, view, playerIds, translation?, scale?)` — projects a slice of a large world into the `0–100` viewport; optional `translation`/`scale` inset the projection into part of the screen (see §13 / §13.1).
- `Shapes.POLYGON | LINE` — shape type enum (`CIRCLE` exists but is not rendered).
- `Physics.getPath(...)` — **straight-line paths only** (no gravity, no arcs). For ballistics (artillery arcs, thrown objects), integrate yourself in `tick()`: `vy += GRAVITY; x += vx; y += vy;` with a few substeps per tick so fast projectiles don't tunnel through thin geometry.
- `TerrainGenerator` — generates **maze-style wall grids** (cells with open/blocked edges), not heightmaps. For rolling-hills/silhouette terrain, build your own heightmap (layered sines work well) and render it as one polygon — mind the ~126-vertex cap (§6).

---

## 13. Large scrolling worlds and per-player cameras (`ViewableGame`)

Everything above renders directly into the shared `0–100` plane, where every player sees the same thing. For games with a **world larger than one screen** (scrolling levels, top-down arenas, anything with a camera) or **per-player cameras** (each player sees their own region), extend **`ViewableGame`** instead of `Game`.

`ViewableGame` gives you a large square **world plane** of size `planeSize × planeSize` (in its own world units), plus a separate **view root** that is what clients actually render. The rendered viewport is **always `0–100`** — you project a rectangular slice of the big world into that `0–100` viewport, per player. This is how you get cameras, scrolling, and split per-player views in one shared game.

### Setup

```js
const { ViewableGame, GameNode, Colors, Shapes, ShapeUtils, ViewUtils } = require('squish-142');

class MyWorld extends ViewableGame {
    constructor() {
        super(1000);   // world is 1000 x 1000 world-units. Call super(planeSize), NOT super().
        this.playerViews = {};
        // ... build world content (Approach A) or keep entities as plain data (Approach B)
    }

    getLayers() {
        return [{ root: this.getViewRoot() }];   // render the VIEW root, not the world plane
    }
}
```

API added by `ViewableGame`:
- `super(planeSize)` — **required**; sets up the world plane and the view root. (Plain `Game` uses `super()` with no args; `ViewableGame` needs the size.)
- `getPlane()` — the world plane `Shape` (size `planeSize`). For the built-in projection approach, add your world content as children of this.
- `getPlaneSize()` / `updatePlaneSize(n)` — read / change the world size.
- `getViewRoot()` — the **render root**. It starts **empty**. Whatever you want on screen must be added here, normally per-player view roots restricted with `playerIds`.

> **Critical:** with `ViewableGame`, `getViewRoot()` is empty by default and the world plane is **not** rendered directly. If you build a world in `getPlane()` but never put a projected view under `getViewRoot()`, **players see a blank screen.**

A "view" is a rectangle into the world: `{ x, y, w, h }` in world units. You render the slice of the world inside that rectangle, scaled to fill the `0–100` viewport.

### Approach A — built-in projection with `ViewUtils.getView`

Build the world once in `getPlane()`, then per player project a view window into a render root. `ViewUtils.getView(plane, view, playerIds)` clones the world nodes inside `view`, translates/clips them into `0–100`, and tags them for `playerIds`. (It has two more optional args, `translation` and `scale`, for placing the projection in only part of the screen — see §13.1.):

```js
handleNewPlayer({ playerId }) {
    const view = { x: 0, y: 0, w: 100, h: 100 };   // window into the world, in world units

    // A solid backdrop this player always sees, so they never see blank space:
    const playerRoot = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
        fill: Colors.COLORS.BLACK,
        playerIds: [playerId]
    });
    playerRoot.addChild(ViewUtils.getView(this.getPlane(), view, [playerId]));

    this.playerViews[playerId] = { view, root: playerRoot };
    this.getViewRoot().addChild(playerRoot);
}

// To move a player's camera, recompute the view and rebuild that player's projection:
panCamera(playerId, dx, dy) {
    const pv = this.playerViews[playerId];
    pv.view = { ...pv.view, x: pv.view.x + dx, y: pv.view.y + dy };
    pv.root.node.clearChildren();
    pv.root.node.addChild(ViewUtils.getView(this.getPlane(), pv.view, [playerId]));
    pv.root.node.onStateChange();
}
```

### Approach B — manual projection (best for camera-follow / many moving entities)

Keep world entities as **plain data** (not nodes), and rebuild each player's view nodes yourself whenever they move or each tick. Full control — e.g. a camera centered on the player. World→view transform: `viewCoord = ((world − viewOrigin) / viewSize) * 100`.

```js
createPlayerView(playerId) {
    const player = this.players[playerId];
    const { w: viewW, h: viewH } = player.view;     // camera window size, in world units
    const viewX = player.x - viewW / 2;             // center the camera on the player
    const viewY = player.y - viewH / 2;

    const viewRoot = new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),   // viewport is always 0–100
        fill: [50, 50, 50, 255],
        playerIds: [playerId]
    });

    const toView = (wx, wy, wsize) => ({
        x: ((wx - viewX) / viewW) * 100,
        y: ((wy - viewY) / viewH) * 100,
        size: (wsize / viewW) * 100
    });

    // player is always drawn centered:
    const ps = (player.size / viewW) * 100;
    viewRoot.addChild(new GameNode.Shape({
        shapeType: Shapes.POLYGON,
        coordinates2d: ShapeUtils.rectangle(50 - ps / 2, 50 - ps / 2, ps, ps),
        fill: player.color, playerIds: [playerId]
    }));

    for (const e of this.enemies) {
        const r = toView(e.x, e.y, e.size);
        viewRoot.addChild(new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(r.x - r.size / 2, r.y - r.size / 2, r.size, r.size),
            fill: e.color, playerIds: [playerId]
        }));
    }
    return viewRoot;
}

// On movement, swap the player's view root under getViewRoot():
updatePlayerView(playerId) {
    const player = this.players[playerId];
    if (player.viewRoot) this.getViewRoot().removeChild(player.viewRoot.node.id);
    player.viewRoot = this.createPlayerView(playerId);
    this.getViewRoot().addChild(player.viewRoot);
    player.viewRoot.node.onStateChange();
}
```

### 13.1 Projecting into a sub-region (static frame around a scrolling viewport)

`getView` takes two optional trailing arguments that let you place the projection somewhere other than the full screen:

```js
ViewUtils.getView(plane, view, playerIds, translation, scale)
```

- `translation` — `{ x, y, filter? }`. After a node is projected, shift it by `x`/`y` (plane units). The optional `filter(node) => boolean` applies the shift to only the nodes it returns true for.
- `scale` — `{ x, y }`. Multiplies the projected coordinates per axis; values `< 1` shrink the projection so it fills only part of the viewport.

Per-vertex transform order is: subtract the view origin and clamp to `0–100`, **then** multiply by `scale`, **then** add `translation`, then clamp again.

This is how you keep **static UI fixed on screen while a world region scrolls inside an inset panel** — the exact pattern the Homegames dashboard uses: a search box and scroll arrows are plain `0–100` nodes, and the scrollable game grid is a `getView` projection scaled down and pushed below them.

```js
renderForPlayer(playerId) {
    const root = this.playerRoots[playerId];          // full-screen node tagged [playerId]

    // 1) static chrome: plain nodes, fixed position, NOT projected
    root.node.addChild(this.buildToolbar(playerId));  // e.g. the search field from §9

    // 2) the scrollable world, projected into the lower/inset part of the screen
    const view = this.playerStates[playerId].view;     // { x, y, w, h } in world units
    root.node.addChild(ViewUtils.getView(
        this.getPlane(), view, [playerId],
        { x: 12.5, y: 18 },        // push the projection right + down, clear of the toolbar
        { x: 0.75, y: 0.75 }       // shrink it to leave margins
    ));
    root.node.onStateChange();
}
```

Gotchas:
- The projection includes only nodes that **overlap** the `view` rectangle (a collision test against the plane's children), so off-screen world content is free — but a node straddling the view edge has its vertices **clamped to `0–100` individually**, which can distort a shape that's half in and half out. Size views so content isn't sliced, or accept the clamp.
- `getView` returns a brand-new subtree each call. To scroll or pan, rebuild that player's projection (`clearChildren()` + re-add, or swap the subtree) and `onStateChange()` — see the `panCamera` example above.
- `onClick` survives projection (the clone keeps its handler), so projected world nodes stay tappable. But the clones cover the viewport, so a **tap-anywhere steering control needs a per-player tap-catcher drawn above the projected view** (§9.1) — an `onClick` on the player's backdrop node gets swallowed by the world clones on top of it.
- **`getView` overwrites `playerIds` on every clone** with the viewing player's id. World-space nodes cannot stay private through projection — a node scoped to player A in the world will still appear in player B's projected view if it's inside B's view rectangle. Keep per-player-secret UI in **screen space** (plain `0–100` nodes with `playerIds`), not in the world.
- **Cost scales with visible nodes × players × ticks** — every camera update clones every node in view. Keep the world sparse (dozens of nodes in view, not hundreds), tick at 10–20, and prefer a camera-follow clamp like `view.x = clamp(shipX - 50, 0, WORLD - 100)`.

**Choosing:** use plain `Game` for single-screen games (most party/casual games). Use `ViewableGame` only when the world exceeds one screen or players need different cameras. Approach A is less code when the world is mostly static nodes; Approach B is better for smooth camera-follow and lots of moving entities. Either way: clean up a player's view root in `handlePlayerDisconnect`, and `getLayers()` returns `[{ root: this.getViewRoot() }]`.

---

## 14. Complete, correct examples

### 14.1 Single-player click game (event-driven, no tick)

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class ClickCounter extends Game {
    static metadata() {
        return {
            squishVersion: '142',
            name: 'Click Counter',
            author: 'AI',
            description: 'Tap the square to score points.',
            aspectRatio: { x: 16, y: 9 }
        };
    }

    constructor() {
        super();
        this.score = 0;

        this.base = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
            fill: COLORS.HG_BLUE
        });

        this.scoreText = new GameNode.Text({
            textInfo: { text: 'Score: 0', x: 50, y: 12, size: 4, align: 'center', color: COLORS.WHITE }
        });

        this.button = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(35, 35, 30, 30),
            fill: COLORS.CANDY_RED,
            onClick: (playerId, x, y) => {
                this.score += 1;
                this.scoreText.node.text = {
                    text: `Score: ${this.score}`, x: 50, y: 12, size: 4, align: 'center', color: COLORS.WHITE
                };
                this.base.node.onStateChange();   // REQUIRED after mutating text
            }
        });

        this.base.addChildren(this.scoreText, this.button);
    }

    getLayers() {
        return [{ root: this.base }];
    }
}

module.exports = ClickCounter;
```

### 14.2 Multiplayer movement game (players join, move with keys, tick loop)

```js
const { Game, GameNode, Colors, Shapes, ShapeUtils } = require('squish-142');
const { COLORS } = Colors;

class Movers extends Game {
    static metadata() {
        return {
            squishVersion: '142',
            name: 'Movers',
            author: 'AI',
            description: 'Everyone gets a square. Move with arrows or WASD.',
            aspectRatio: { x: 16, y: 9 },
            tickRate: 30
        };
    }

    constructor() {
        super();
        this.players = {};          // playerId -> { node, vx, vy }
        this.base = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(0, 0, 100, 100),
            fill: COLORS.ALMOST_BLACK
        });
    }

    handleNewPlayer({ playerId, info }) {
        const square = new GameNode.Shape({
            shapeType: Shapes.POLYGON,
            coordinates2d: ShapeUtils.rectangle(47, 47, 6, 6),
            fill: Colors.randomColor(['ALMOST_BLACK'])   // exclude by NAME (string)
        });
        const name = new GameNode.Text({
            textInfo: { text: info?.name || 'player', x: 50, y: 5, size: 1.5, align: 'center', color: COLORS.WHITE },
            playerIds: [playerId]   // each player sees only their own name banner
        });
        this.players[playerId] = { node: square, vx: 0, vy: 0 };
        this.base.addChildren(square, name);
    }

    handlePlayerDisconnect(playerId) {
        const p = this.players[playerId];
        if (p) {
            this.base.removeChild(p.node.id);
            delete this.players[playerId];
        }
    }

    handleKeyDown(playerId, key) {
        const p = this.players[playerId];
        if (!p) return;
        if (key === 'ArrowUp' || key === 'w') p.vy = -1;
        else if (key === 'ArrowDown' || key === 's') p.vy = 1;
        else if (key === 'ArrowLeft' || key === 'a') p.vx = -1;
        else if (key === 'ArrowRight' || key === 'd') p.vx = 1;
    }

    handleKeyUp(playerId, key) {
        const p = this.players[playerId];
        if (!p) return;
        if (key === 'ArrowUp' || key === 'w' || key === 'ArrowDown' || key === 's') p.vy = 0;
        if (key === 'ArrowLeft' || key === 'a' || key === 'ArrowRight' || key === 'd') p.vx = 0;
    }

    tick() {
        let changed = false;
        for (const id in this.players) {
            const p = this.players[id];
            if (p.vx === 0 && p.vy === 0) continue;
            const x = p.node.node.coordinates2d[0][0];
            const y = p.node.node.coordinates2d[0][1];
            const nx = Math.max(0, Math.min(94, x + p.vx));   // clamp to plane (square is 6 wide)
            const ny = Math.max(0, Math.min(94, y + p.vy));
            p.node.node.coordinates2d = ShapeUtils.rectangle(nx, ny, 6, 6);
            changed = true;
        }
        if (changed) this.base.node.onStateChange();   // ONE notify per tick
    }

    getLayers() {
        return [{ root: this.base }];
    }
}

module.exports = Movers;
```

### 14.3 Bots and enemy AI (games must be fun with one player)

A game that needs 2+ players demos badly. The shipped catalog pattern: **bots fill empty slots at match start, and a disconnecting player's avatar is handed to a bot brain** (`agent.playerId = null; agent.isBot = true;`) so rounds never break. Keep entities as plain data (`{ x, y, angle, isBot, ... }`) and run bot logic in `tick()`.

> **Last-man-standing logic must special-case solo play.** The naive check `if (alivePlayers.length === 1) declareWinner(...)` ends a single-player session **the instant it starts** — the only player is always the last one alive. Either require ≥2 participants at round start (fill with bots), or in solo sessions switch the win condition to survival time / score and only use "last alive" when the round began with multiple combatants.

Two building blocks cover most enemies:

```js
// Wander: walk forward, turn away from walls, jitter occasionally.
botWander(bot) {
    const aheadX = bot.x + Math.cos(bot.angle) * 0.7;
    const aheadY = bot.y + Math.sin(bot.angle) * 0.7;
    if (this.isBlocked(aheadX, aheadY)) {
        bot.angle += (Math.random() < 0.5 ? 1 : -1) * (Math.PI / 2 + (Math.random() - 0.5) * 0.8);
    } else if (Math.random() < 0.04) {
        bot.angle += (Math.random() - 0.5) * 1.2;   // occasional random turn
    }
    this.moveWithCollision(bot, 0.75);
}

// Line of sight: sample the segment between two entities for obstacles.
hasLineOfSight(from, to) {
    const dist = Math.hypot(to.x - from.x, to.y - from.y);
    for (let step = 0.3; step < dist - 0.2; step += 0.3) {
        const t = step / dist;
        if (this.isBlocked(from.x + (to.x - from.x) * t, from.y + (to.y - from.y) * t)) return false;
    }
    return true;
}
```

**The fairness rules — this is what separates a fun bot from an aimbot.** A bot that acquires a target and fires in the same tick with perfect aim is unbeatable and feels terrible. Combat bots must run a three-state loop:

1. **Acquire** — scan a few times per second (not every tick), only when the bot's own cooldown is ready, only within a capped engage range, and only with line of sight.
2. **Telegraph** — on acquiring, the bot **stops moving and visibly turns toward the target for 0.5–1s** (`aimTicks` countdown, rotating a capped amount per tick). This is the victim's window to dodge or fight back. Cancel the aim if the target breaks line of sight, leaves range, or becomes invulnerable.
3. **Fire with error** — when the telegraph expires, fire with **aim error that grows with distance** (`angle = perfect + (Math.random() - 0.5) * (0.1 + dist * 0.05)`), then take a **cooldown 2–3× longer than a human's**.

Difficulty knobs, in order of impact: telegraph duration, aim-error slope, bot cooldown, engage range. Tune by simulation: a *stationary* target at mid-range should survive ~2s after being spotted; a moving one much longer. Also respect spawn-protection windows, and never let bots re-acquire while still cooling down.

### 14.4 Pseudo-3D: a first-person raycaster (yes, really)

Because every player can have a fully private view (`playerIds`), and a view is just rectangles, the server can render **real-time first-person 3D**: give each player a strip of vertical wall-slice rects and recompute them every tick with a grid raycast. This is the most advanced pattern in the catalog (`prism-3d`), and it works — a multiplayer FPS in one file.

The essentials:

- **One slice rect per screen column, created ONCE per player at join** (stable node ids — never recreate them), scoped `playerIds: [pid]`. ~48–56 columns reads convincingly retro. Each tick, mutate every slice's `coordinates2d` + `fill`, then one `onStateChange()`.
- **DDA raycast per column** (Lodev camera-plane style — use the *perpendicular* distance so walls don't fisheye):

```js
const dirX = Math.cos(p.angle), dirY = Math.sin(p.angle);
const planeX = -dirY * 0.66, planeY = dirX * 0.66;        // ~66° FOV
for (let col = 0; col < COLS; col++) {
    const cameraX = (2 * col) / (COLS - 1) - 1;
    // step the ray cell-by-cell through the grid (DDA) until it hits a wall,
    // tracking which axis was crossed last (side) and the perpendicular dist
    const { dist, side, wallType } = this.castRay(p.x, p.y, dirX + planeX * cameraX, dirY + planeY * cameraX);
    const h = Math.min(100, HEIGHT_K / dist);              // wall slice height
    const shade = Math.max(0.1, 1.15 / (1 + dist * 0.24)) * (side ? 0.72 : 1);
    slice.node.coordinates2d = ShapeUtils.rectangle(col * COL_W, 50 - h / 2, COL_W + 0.05, h);
    slice.node.fill = wallColor(wallType).map(c => Math.round(c * shade));
    this.lastDists[col] = dist;                            // saved for sprite occlusion
}
```

- **Ceiling, floor, and horizon are identical for everyone → shared nodes** (no `playerIds`). Same for the minimap and score strip. Only the slices and sprites are per-player.
- **Other entities are billboard sprites**: camera-plane transform (`transX/transY`), screen x = `50 * (1 + transX / transY)`, height = `K / transY`, and **occlude by comparing `transY` against `lastDists[column]`** from the wall pass. One rect + one detail rect per visible entity is plenty.
- **Budget honestly**: per-player bandwidth ≈ (shared nodes + own scoped nodes) × ~55 bytes × tickRate. 56 columns at tickRate 12 ≈ 100 KB/s per player — fine on LAN, borderline over a relay. `COLS` and `tickRate` are the knobs; cap humans at ~4 (bots need no view). tickRate 10–14 reads as intentionally retro.
- Movement: apply moves on input events (key repeat / held-tap re-clicks give continuity), slide along walls by resolving the x and y axes independently, and keep a body radius so players don't clip corners.
- Controls: tap left/right thirds = turn, center = forward, plus a FIRE button — with the tap catcher **above the slices, below the buttons** (§9.1), and the crosshair *below* the catcher so it can't eat center taps.

---

## 15. Idioms and anti-patterns (checklist before you output)

### 15.1 Write code where a typo can't hide

The validation sandbox runs your game for a few seconds but **never presses a key or clicks a button** (§2). Any code that only runs after input — key handlers, `onClick`s, everything behind a `gameStarted`/phase gate — ships unexecuted. When a generated game crashes in production, it is nearly always a `ReferenceError` in exactly that code, and nearly always from the same cause: **two near-identical copy-pasted blocks with a fleet of similar positional locals** (`leftPivotX`, `pivotY`, `leftTipX`, `leftTipY`, `leftX1`, `leftY2`, `rightX1`, ...) where one block references a name that was never defined (`leftPivotY` in a scope that only has `pivotY`). The variable soup makes the typo invisible to a re-read, and the input gate makes it invisible to the sandbox. Three rules:

1. **Mirrored or repeated geometry comes from ONE helper called N times — never from duplicated blocks.** Left/right chopsticks, two paddles, four walls, per-player HUDs: write the math once (like `thickLine` in §7.1), call it with mirrored arguments. Fewer variable names means fewer chances to typo one, and the single implementation gets exercised on every path instead of hiding a broken copy.

```js
// GOOD — one implementation, two calls:
this.leftStick.node.coordinates2d  = thickLine(cx - gap / 2, py, cx - gap / 4, ty, 1.5);
this.rightStick.node.coordinates2d = thickLine(cx + gap / 2, py, cx + gap / 4, ty, 1.5);

// BAD — 20 lines of trig duplicated for "left" and "right" with 16 similar
// local names; this is where `leftPivotY` (undefined) slips in unnoticed.
```

2. **Initialize every field you'll later test, at creation time.** `if (obj.captured === false)` is never true when `captured` was never assigned — `undefined === false` is `false`, so the mechanic silently never fires. Set `captured: false` in the object literal when you create the entity, and prefer truthiness checks (`if (!obj.captured)`), which treat "unset" and "false" the same.

3. **Before you output, execute every gated method in your head once.** For each key handler, `onClick`, and phase-gated branch: read every identifier and confirm it is defined in that scope, and confirm every `this.foo` was assigned in the constructor. This five-second pass is the test the sandbox cannot run for you.

### 15.2 The checklist

Do:
- [ ] `module.exports = TheClass;` at the end (export the class, not an instance).
- [ ] `require('squish-142')` and `squishVersion: '142'` agree.
- [ ] Call `super()` first thing in the constructor.
- [ ] Build a single root `this.base` shape sized `rectangle(0,0,100,100)`; return it from `getLayers()` as `[{ root: this.base }]`. (For worlds bigger than one screen or per-player cameras, extend `ViewableGame` and render `getViewRoot()` instead — §13.)
- [ ] Call `onStateChange()` on the root after any direct property mutation (§4) — once per tick, and only when something changed (§4.1).
- [ ] Gate `tick()` on a game phase, and create every node `tick()` touches in the constructor (§10) — it starts firing at construction, before anyone joins or presses start.
- [ ] Pre-allocate pools for particles/trails/projectiles and mutate them in place; hide dead ones with zero-size + transparent fill (§4.1).
- [ ] Restart / "play again" by resetting your own state and nodes in place — the game runs in Node on the server; there is no page to reload (§1).
- [ ] Clamp every computed color channel to an integer `0–255` — out-of-range wraps, it doesn't clamp (§6).
- [ ] Write mirrored/repeated geometry as one helper called N times, and mentally execute every input-gated method before output — the sandbox never presses keys, so typos there ship (§15.1).
- [ ] Initialize every entity field you'll later test (`captured: false` at creation) and prefer truthy checks over `=== false` (§15.1).
- [ ] Use `this.setTimeout` / `this.setInterval` (tracked) for timers.
- [ ] Clean up a leaving player's nodes in `handlePlayerDisconnect`.
- [ ] Size click/tap targets generously and support tap-first or both arrows+WASD.
- [ ] Keep everything in `0–100` coordinate space.
- [ ] Make grouping/"layer" containers **zero-size** (`rectangle(0,0,0,0)`) so they never swallow clicks (§9.1); full-screen tap steering goes on a dedicated tap-catcher above the playfield, below the buttons.
- [ ] Give every roster/scoreboard a per-player scoped "YOU" marker, and secrets games a per-player privacy anchor (§8) — frameless sessions have no chrome and no guaranteed name.
- [ ] Give each game a distinct color identity (don't default every game to dark-navy + neon); keep action games at tickRate 15–30.

Don't:
- [ ] Don't forget `onStateChange()` — mutating `coordinates2d`/`fill`/`text` without it shows nothing.
- [ ] Don't put `onClick` on a `Text` node — it's silently ignored. Build buttons as a clickable `Shape` with a `Text` on top (§7.2.1).
- [ ] Don't put `'\n'` in a `Text` node — it renders as ONE line; make one `Text` node per line (§7.2).
- [ ] Don't invent `COLORS.*` names — a name outside the §6 list is `undefined` and the shape silently renders with no fill (invisible). Use the list or an explicit `[r,g,b,a]`.
- [ ] Don't pass `border` as an object — it's a **number** (outline width), and you must also set `color` for the stroke (§7.1).
- [ ] Don't pass color **arrays** to `Colors.randomColor()` — it excludes by **name** strings (§6).
- [ ] Don't expect circles/true angles at non-`{1,1}` aspect ratios — the plane is stretched; use `{x:1,y:1}` for geometry (§5).
- [ ] Don't `require` Node built-ins, hit the network/filesystem, read `process.env`, or use `eval`/`new Function`.
- [ ] Don't spin up one game instance per player — it's one shared instance; use `playerIds` for per-player views.
- [ ] Don't tag gameplay entities (ships, avatars, bullets) with `playerIds: [ownerId]` — that's **visibility**, not ownership; every other player stops seeing them (§8). Scope only genuinely private UI.
- [ ] Don't derive player ids (array index + 1, join order) — use the exact ids the server passes to your handlers (§8).
- [ ] Don't touch browser globals — no `window`, `document`, `location.reload()`, `alert` — this is Node on a server; a `ReferenceError` crashes the session (§1, §2).
- [ ] Don't create/remove nodes every tick (particles, trails, recreating a `Text` node to change its string) — pool and mutate instead (§4.1); reassign `node.text` for label updates.
- [ ] Don't call `onStateChange()` unconditionally every tick — every notify re-squishes and re-broadcasts the whole tree; use a changed flag (§4.1).
- [ ] Don't spawn "just off-screen" at negative coordinates — they clamp to `0` and the entity sits on the edge; only `100–255` (right/bottom) is really off-screen (§6).
- [ ] Don't put `effects` glow on every entity — canvas `shadowBlur` is expensive client-side; glow a handful of focal nodes (§4.1).
- [ ] Don't end a last-man-standing round when only one player ever joined — require ≥2 at round start or use bots (§14.3).
- [ ] Don't invent asset ids. If you have none, draw with shapes and text instead of `Asset` nodes.
- [ ] Don't use coordinates outside `0–100` expecting them to be visible.
- [ ] Don't give a single node more than ~126 vertices — the wire frame overflows (§6).
- [ ] Don't put full-screen invisible containers above clickable things — the hit-test stops at the topmost containing node and drops the click (§9.1).
- [ ] Don't animate `fill` alpha to fade a node — it renders opaque for any value ≥ 1; fade via `color` alpha instead, and set an explicit `color` on nodes drawn after faded ones (§7.4).
- [ ] Don't set `effects = {}` to clear an effect — use `null` (§7.4). Don't put `effects` on `Text` (not supported; use offset-copy glow).
- [ ] Don't scope with `playerIds: [0]` expecting "everyone" — `[0]` means **nobody**; omit `playerIds` (empty) for everyone (§8).
- [ ] Don't rely on sub-`0.01` precision — per-frame motion below ~`0.01` units rounds away (§6). Keep deltas ≥ ~0.05 or accumulate off-node.
- [ ] Don't use the `crop*` asset fields on `squish-142`/`139` — cropping needs `squish-140`+ (§7.3.1); on older versions they're ignored.
- [ ] Don't block the event loop (no busy loops, no synchronous long work); drive motion from `tick()`.
- [ ] Don't assume a keyboard exists on mobile — provide on-screen controls if keys are core.

---

## 16. Quick reference card

```
require('squish-142')  ->  { Game, GameNode, Colors, Shapes, ShapeUtils, GeometryUtils, Asset, Physics, ... }

Game hooks:   metadata() [static, required] · constructor()->super() · getLayers()->[{root}]
              handleNewPlayer({playerId,info,settings,clientInfo}) · handlePlayerDisconnect(playerId)
              handleKeyDown(playerId,key) · handleKeyUp(playerId,key) · tick() · canAddPlayer() · close()

Nodes:        GameNode.Shape({ shapeType, coordinates2d, fill, color, border, onClick, effects, playerIds })  // clickable
              border = NUMBER (outline width), NOT an object; stroke uses `color` -> set both. fill=interior.
              round shape: build a many-sided polygon (CIRCLE doesn't render). rotate verts with trig (§7.1).
              max ~126 vertices per node (§6). effects:{shadow:{color,blur}} = glow; clear with null, never {} (§7.4).
              GameNode.Text({ textInfo:{ text,x,y,size,align,color,font }, playerIds })       // NO onClick
              GameNode.Asset({ coordinates2d, assetInfo:{ key:{pos:{x,y},size:{x,y},startTime} }, playerIds })  // clickable
              Asset crop (squish-140+): assetInfo.key.{cropLeft,cropTop,cropRight,cropBottom} = % inset per edge -> spritesheets (§7.3.1)
Button:       no button node + Text isn't clickable -> clickable Shape (onClick) with a Text node on top (§7.2.1)

Tree ops:     n.addChild(c) · n.addChildren(a,b) · n.removeChild(id) · n.clearChildren([keepIds])
              n.findChild(id) · n.update({fill,coordinates2d}) · n.showFor(pid) · n.hideFor(pid)
NOTIFY:       n.node.onStateChange()   // after direct field mutation; tree ops notify for you
Cost:         every notify re-squishes + re-broadcasts the WHOLE tree to every player (bursts coalesce
              into one flush per turn) -> notify once per tick, ONLY when changed; POOL particle/trail/
              bullet nodes (create once in constructor, mutate, hide with zero-size + fill [0,0,0,0]) —
              never addChild/removeChild per tick; glow a few focal nodes only (shadowBlur is expensive) (§4.1)
Env:          Node on the server — NO window/document/location/alert; "play again" = reset state in place,
              never location.reload() (§1)
tick():       starts at construction, fires on menus too -> gate on phase; create every node tick()
              touches in the constructor (a throw in tick = crashed session = rejected) (§10)

Shapes:       Shapes.POLYGON | LINE   (CIRCLE constant exists but does NOT render — don't use)
Coords:       ShapeUtils.rectangle(x,y,w,h) · ShapeUtils.triangle(x1,y1,x2,y2,x3,y3) · plane is 0..100
Colors:       Colors.COLORS.RED ... ([r,g,b,a] 0..255) · Colors.randomColor(['BLACK',...])  // exclude by NAME, not value
              channels are raw bytes: out-of-range WRAPS (alpha 400 -> 144) -> clamp computed values (§6)
              ONLY the ~100 names listed in §6 exist — an invented name = undefined = invisible shape (no error)
Text limits:  '\n' does NOT line-break (single fillText call) -> one Text node per line (§7.2)
Typo safety:  sandbox never presses keys/clicks -> mirrored geometry = ONE helper called twice (thickLine, §7.1);
              init fields you'll test (captured: false); hand-trace every gated handler before output (§15.1)
Off-plane:    coords clamp to [0,255] on the wire — negatives pin to 0 (no off-screen left/top);
              100..255 = off right/bottom; enter from left/top by spawning AT the edge moving inward (§6)
Aspect:       plane is 0..100 but stretched to aspectRatio -> use {1,1} for circles/orbits/true angles (§5)
              text height in y-units = size * (aspectX/aspectY); square rect: h = w * (x/y) (§5)
Hide a node:  playerIds = [0] (nobody) or fill [0,0,0,0]
Fade a node:  animate `color` alpha (fill alpha is opaque for any value >= 1) (§7.4)
onClick:      (playerId, x, y) => {}    // Shape/Asset only
Click routing: topmost CONTAINING node wins, clickable or not -> containers must be rectangle(0,0,0,0);
              full-screen taps need a tap-catcher above the playfield, below the buttons (§9.1)
text input:   Shape/Text input:{ type:'text', oninput:(playerId, value)=>{} }  // MODAL prompt; one-shot entry
file upload:  input:{ type:'file', oninput:(playerId, bytes, meta)=>{} }  // bytes = byte array (<=5MB),
              meta = { kind:'image'|'audio'|null, contentType, fileName }; register via addAsset (§9)
Live typing:  held keys re-send keydown every ~33ms with NO delay -> gate them like an OS keyboard:
              fresh press (not seen >400ms) types instantly; held repeats after 450ms at ~18cps (§9 Keyboard)
hover:        Shape/Asset onHover(pid) / offHover(pid)   // cosmetic only; no hover on touch
playerIds:    [] / omitted = everyone (default) · [id,...] = only those · [0] = NOBODY (hide)
              VISIBILITY, not ownership: leave avatars/ships/bullets UNSCOPED or other players can't
              see them; input already routes per player via handler args; never derive ids from indices (§8)
              scoping covers the subtree; players with NO scoped nodes get the UNFILTERED state ->
              secrets games: per-player zero-size privacy anchor + scoped "YOU" markers (§8)

Rounds:       last-man-standing must special-case solo (1 player alive at spawn != winner) — require >=2
              at round start or fill with bots (§14.3)

Bots:         fill empty slots at match start; hand disconnected players' avatars to a bot brain (§14.3)
              fair combat bots: acquire (LOS + range + own cooldown) -> TELEGRAPH 0.5-1s (stop, turn toward
              target) -> fire with distance-scaled aim error -> 2-3x human cooldown. NEVER snap-fire.
3D:           per-player raycast view = N playerIds-scoped slice rects (stable ids) mutated per tick (§14.4)
              share floor/ceiling/HUD; occlude sprites vs per-column wall dists; COLS x tickRate = bandwidth

Big worlds:   extend ViewableGame · super(planeSize) · getPlane()/getPlaneSize() = world
              getViewRoot() = render root (starts EMPTY) · getLayers()->[{root:getViewRoot()}]
              ViewUtils.getView(plane,{x,y,w,h},[pid], translation?, scale?) projects a world slice into 0..100
                translation={x,y,filter?} scale={x,y} -> inset the projection (static frame + scroll region, §13.1)
```
