// src/RuleEngine.js

export function applyRules(todos, rules) {
  // For each todo, test all rules and apply actions if condition matches
  // Conditions & actions are simple expressions:
  // Condition example: content.includes("urgent")
  // Action example: highlight | delete | prefix:"[!]"
  // Actions supported: highlight (returns flagged item), delete (filters out), prefix:"text"

  return todos.filter(todo => {
    let keep = true;
    let modifiedContent = todo.content;
    let highlight = false;

    for (const rule of rules) {
      const cond = rule.condition.toLowerCase();
      const action = rule.action.toLowerCase();

      // Simple parser for condition (only content.includes)
      if (cond.startsWith('content.includes(')) {
        const keyword = cond.match(/content\.includes\(["'](.+?)["']\)/)?.[1];
        if (keyword && todo.content.toLowerCase().includes(keyword)) {
          // Perform action
          if (action === 'delete') {
            keep = false;
            break;
          }
          if (action === 'highlight') {
            highlight = true;
          }
          if (action.startsWith('prefix:')) {
            const prefixText = action.match(/prefix:\s*["'](.+?)["']/)?.[1];
            if (prefixText) {
              modifiedContent = prefixText + modifiedContent;
            }
          }
        }
      }
    }

    if (!keep) return false;
    todo.modifiedContent = modifiedContent;
    todo.highlight = highlight;
    return true;
  });
}
