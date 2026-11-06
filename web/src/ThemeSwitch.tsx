// Light, Dark, or the system's: kept in this browser (theme.ts).
import { createSignal } from "solid-js";
import { applyTheme, readTheme, type ThemeChoice } from "./theme";

export default function ThemeSwitch() {
  const [t, setT] = createSignal<ThemeChoice>(readTheme());
  const choose = (v: ThemeChoice) => { setT(v); applyTheme(v); };
  return <label class="check"><span class="muted">Theme</span>
    <select value={t()} onChange={(e) => choose(e.currentTarget.value as ThemeChoice)}>
      <option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option>
    </select>
  </label>;
}
