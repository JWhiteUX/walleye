import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src-tauri", "src/shared/bindings", "playwright-report", "test-results"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: { ecmaVersion: 2022, globals: globals.browser },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      // Captured data is hostile: never render it as HTML.
      "no-restricted-syntax": [
        "error",
        { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: "Never inject HTML; capture data is hostile." },
        { selector: "JSXAttribute[name.name='srcDoc']", message: "Never inject HTML; capture data is hostile." },
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "Never inject HTML; capture data is hostile." },
        { selector: "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]", message: "Never inject HTML; capture data is hostile." },
        { selector: "NewExpression[callee.name='Function']", message: "No dynamic code." },
        { selector: "CallExpression[callee.object.name='window'][callee.property.name='open']", message: "The app opens no windows or URLs." },
      ],
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Never inject HTML; capture data is hostile." },
        { property: "outerHTML", message: "Never inject HTML; capture data is hostile." },
        { property: "srcdoc", message: "Never inject HTML; capture data is hostile." },
      ],
    },
  },
);
