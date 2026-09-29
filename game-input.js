const { Buttons, mapInputs } = require('homepad');
const standard = require('homepad/gamepad-mappings/standard');

const clamp = (value, min, max) => Number.isFinite(value) ? Math.max(min, Math.min(max, value)) : 0;
const neutralState = () => ({
    buttons: Object.fromEntries(Object.values(Buttons).map(key => [key, { value: 0, pressed: false }])),
    sticks: Object.fromEntries(Object.keys(standard.sticks).map(key => [key, { value: 0 }])),
});

// Shared by hosted and browser-local sessions. Games never import Homepad or
// know about browser APIs; they declare keys or consume normalized analog state.
class GameInput {
    constructor(game) {
        this.game = game;
        this.bindings = game.constructor.metadata?.().gamepadBindings || {};
        this.players = new Map();
    }

    _player(id) {
        if (!this.players.has(id)) this.players.set(id, { keyboard: new Set(), pads: new Map() });
        return this.players.get(id);
    }

    _keys(player) {
        return new Set([...player.keyboard, ...Array.from(player.pads.values()).flatMap(pad => [...pad.keys])]);
    }

    keyDown(id, key) {
        this._player(id).keyboard.add(key);
        this.game.handleKeyDown?.(id, key);
    }

    keyUp(id, key) {
        const player = this._player(id);
        player.keyboard.delete(key);
        if (!this._keys(player).has(key)) this.game.handleKeyUp?.(id, key);
    }

    gamepad(id, message) {
        // Older clients omit index, connected and deltaTime.
        const index = message.gamepadIndex ?? 0;
        if (!Number.isInteger(index) || index < 0 || index > 15) return;
        if (!message.input || typeof message.input !== 'object') return;
        if (message.connected !== false && (!message.input.buttons || !message.input.sticks)) return;
        const state = neutralState();
        if (message.connected !== false) {
            for (const key of Object.keys(state.buttons)) {
                const button = message.input.buttons[key];
                state.buttons[key] = { value: clamp(button?.value, 0, 1), pressed: button?.pressed === true };
            }
            for (const key of Object.keys(state.sticks)) state.sticks[key].value = clamp(message.input.sticks[key]?.value, -1, 1);
        }
        const player = this._player(id);
        const oldKeys = this._keys(player);
        const previous = player.pads.get(index);
        const pressed = Object.keys(state.buttons).filter(key => state.buttons[key].pressed && !previous?.state.buttons[key].pressed);
        const released = Object.keys(state.buttons).filter(key => !state.buttons[key].pressed && previous?.state.buttons[key].pressed);
        const keys = new Set(Object.entries(mapInputs(state, this.bindings)).filter(([, input]) => input.pressed).map(([key]) => key));
        if (message.connected === false) player.pads.delete(index);
        else player.pads.set(index, { state, keys });
        const newKeys = this._keys(player);
        for (const key of oldKeys) if (!newKeys.has(key)) this.game.handleKeyUp?.(id, key);
        // Repeat keys held by this pad. If sources overlap, only their first
        // owner repeats; releasing another source cannot cancel a held key.
        for (const key of keys) {
            const owner = [...player.pads].find(([, pad]) => pad.keys.has(key))?.[0];
            if (!player.keyboard.has(key) && owner === index) this.game.handleKeyDown?.(id, key);
        }
        this.game.handleGamepadInput?.(id, {
            type: 'input', gamepad: true, gamepadIndex: index,
            connected: message.connected !== false,
            deltaTime: message.connected === false ? 0 : clamp(message.deltaTime ?? 1 / 30, 0, 0.1),
            input: state, pressed, released,
        });
    }

    removePlayer(id) {
        const player = this.players.get(id);
        if (!player) return;
        this.players.delete(id);
        for (const key of this._keys(player)) this.game.handleKeyUp?.(id, key);
        for (const [index, pad] of player.pads) {
            this.game.handleGamepadInput?.(id, { type: 'input', gamepad: true, gamepadIndex: index,
                connected: false, deltaTime: 0, input: neutralState(), pressed: [],
                released: Object.keys(pad.state.buttons).filter(key => pad.state.buttons[key].pressed) });
        }
    }
}

module.exports = GameInput;
