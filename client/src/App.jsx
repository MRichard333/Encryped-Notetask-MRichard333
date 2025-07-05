import React, { useEffect, useState } from 'react';

export default function App() {
  const [todos, setTodos] = useState([]);
  const [content, setContent] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [authenticated, setAuthenticated] = useState(
    sessionStorage.getItem('authenticated') === 'true'
  );
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  // For change password UI
  const [showChangePass, setShowChangePass] = useState(false);
  const [currentPass, setCurrentPass] = useState('');
  const [newPass, setNewPass] = useState('');
  const [changePassError, setChangePassError] = useState('');
  const [changePassSuccess, setChangePassSuccess] = useState('');

  // --- Fetch todos
  const fetchTodos = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/todos');
      if (!res.ok) throw new Error('🔐 Unlock required');
      const data = await res.json();
      setTodos(data);
      setError('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // --- Unlock encryption with passphrase
  const unlock = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase }),
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Incorrect passphrase');
      }
      setAuthenticated(true);
      sessionStorage.setItem('authenticated', 'true');
      setPassphrase('');
      setError('');
      fetchTodos();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // --- Logout (lock)
  const logout = async () => {
    await fetch('/api/lock', { method: 'POST' });
    setAuthenticated(false);
    sessionStorage.removeItem('authenticated');
    setTodos([]);
    setError('');
    setShowChangePass(false);
  };

  // --- Add todo
  const addTodo = async () => {
    if (!content.trim()) return;
    try {
      const res = await fetch('/api/todos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to add todo');
      }
      setContent('');
      fetchTodos();
    } catch (err) {
      setError(err.message);
    }
  };

  // --- Delete todo
  const deleteTodo = async (id) => {
    try {
      const res = await fetch(`/api/todos/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to delete todo');
      }
      fetchTodos();
    } catch (err) {
      setError(err.message);
    }
  };

  // --- Change password
  const changePassword = async () => {
    setChangePassError('');
    setChangePassSuccess('');
    if (!currentPass || !newPass) {
      setChangePassError('Please fill in both fields.');
      return;
    }
    if (newPass.length < 6) {
      setChangePassError('New passphrase must be at least 6 characters.');
      return;
    }
    try {
      const res = await fetch('/api/change-passphrase', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassphrase: currentPass, newPassphrase: newPass }),
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || 'Failed to change passphrase');
      }
      setChangePassSuccess('Passphrase changed successfully!');
      setCurrentPass('');
      setNewPass('');
      setShowChangePass(false);
    } catch (err) {
      setChangePassError(err.message);
    }
  };

  useEffect(() => {
    if (authenticated) fetchTodos();
  }, [authenticated]);

  // --- Passphrase unlock screen
  if (!authenticated) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gray-900 text-white px-4">
        <h1 className="text-4xl font-bold mb-4">🔐 Encrypted ToDo</h1>
        <p className="mb-4 text-gray-400 text-center max-w-xs">
          Enter your passphrase to unlock your encrypted todos.
        </p>
        <input
          type="password"
          placeholder="Your passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          className="w-full max-w-xs px-4 py-3 rounded bg-gray-800 border border-gray-600 mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500"
          onKeyDown={(e) => e.key === 'Enter' && unlock()}
          autoFocus
        />
        <button
          onClick={unlock}
          disabled={loading}
          className="w-full max-w-xs py-3 bg-blue-600 hover:bg-blue-700 rounded font-semibold disabled:opacity-60"
        >
          {loading ? 'Unlocking...' : 'Unlock'}
        </button>
        {error && <p className="text-red-400 mt-4 text-center max-w-xs">{error}</p>}
        <p className="mt-6 text-xs text-gray-500 max-w-xs text-center">
          Made with &lt;3 in Canada by{' '}
          <a
            href="https://MRichard333.com"
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-blue-400"
          >
            MRichard333.com
          </a>
        </p>
      </div>
    );
  }

  // --- Main app screen
  return (
    <div className={`${darkMode ? 'dark' : ''}`}>
      <div
        className="min-h-screen bg-gradient-to-br from-indigo-700 via-purple-800 to-gray-900
          dark:from-gray-900 dark:via-slate-800 dark:to-black
          text-gray-900 dark:text-white font-sans transition-all duration-500 bg-[length:200%_200%] animate-gradient-x"
      >
        <div className="max-w-xl mx-auto p-6">
          {/* Header */}
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">🔐 Encrypted ToDo</h1>
            <div className="flex gap-2">
              <button
                onClick={() => setDarkMode(!darkMode)}
                className="text-sm px-3 py-1 border rounded hover:bg-white/10"
                title="Toggle light/dark mode"
              >
                {darkMode ? '☀ Light' : '🌙 Dark'}
              </button>
              <button
                onClick={logout}
                className="text-sm px-3 py-1 border border-red-400 text-red-300 hover:bg-red-600 hover:text-white rounded"
                title="Lock and logout"
              >
                🔒 Lock
              </button>
              <button
                onClick={() => {
                  setShowChangePass((v) => !v);
                  setChangePassError('');
                  setChangePassSuccess('');
                  setCurrentPass('');
                  setNewPass('');
                }}
                className="text-sm px-3 py-1 border border-green-400 text-green-300 hover:bg-green-600 hover:text-white rounded"
                title="Change passphrase"
              >
                🔑 Change Passphrase
              </button>
            </div>
          </div>

          {/* Change Passphrase Form */}
          {showChangePass && (
            <div className="mb-6 p-4 rounded bg-gray-100 dark:bg-gray-800 shadow">
              <h2 className="text-xl font-semibold mb-3">Change Passphrase</h2>
              <input
                type="password"
                placeholder="Current passphrase"
                value={currentPass}
                onChange={(e) => setCurrentPass(e.target.value)}
                className="w-full mb-3 px-3 py-2 rounded border border-gray-400 dark:border-gray-600 bg-white dark:bg-gray-700 text-black dark:text-white"
                autoFocus
              />
              <input
                type="password"
                placeholder="New passphrase"
                value={newPass}
                onChange={(e) => setNewPass(e.target.value)}
                className="w-full mb-3 px-3 py-2 rounded border border-gray-400 dark:border-gray-600 bg-white dark:bg-gray-700 text-black dark:text-white"
                onKeyDown={(e) => e.key === 'Enter' && changePassword()}
              />
              <div className="flex gap-2">
                <button
                  onClick={changePassword}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded"
                >
                  Change Passphrase
                </button>
                <button
                  onClick={() => setShowChangePass(false)}
                  className="px-4 py-2 bg-gray-300 dark:bg-gray-600 rounded hover:bg-gray-400 dark:hover:bg-gray-700"
                >
                  Cancel
                </button>
              </div>
              {changePassError && <p className="text-red-500 mt-2">{changePassError}</p>}
              {changePassSuccess && <p className="text-green-500 mt-2">{changePassSuccess}</p>}
            </div>
          )}

          {/* Add todo input */}
          <div className="flex gap-2 mb-6">
            <input
              type="text"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Enter new task"
              className="flex-1 px-4 py-2 rounded bg-white/90 dark:bg-gray-800 text-black dark:text-white"
              onKeyDown={(e) => e.key === 'Enter' && addTodo()}
            />
            <button
              onClick={addTodo}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded"
            >
              Add
            </button>
          </div>

          {loading && <p>Loading todos...</p>}
          {error && <p className="text-red-400">{error}</p>}

          <ul className="space-y-2">
            {todos.map((todo) => (
              <li
                key={todo.id}
                className="p-3 rounded flex justify-between items-center shadow bg-white/80 dark:bg-gray-800"
              >
                <span>{todo.content}</span>
                <button
                  onClick={() => deleteTodo(todo.id)}
                  className="text-red-500 hover:text-red-700"
                  title="Delete task"
                >
                  ❌
                </button>
              </li>
            ))}
          </ul>

          <footer className="mt-12 text-center text-xs text-gray-400">
            Made with &lt;3 in Canada by{' '}
            <a
              href="https://MRichard333.com"
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-blue-400"
            >
              MRichard333.com
            </a>
          </footer>
        </div>
      </div>
    </div>
  );
}
