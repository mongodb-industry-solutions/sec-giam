'use client';

// A failure in the identity console must not leak what failed: the message is generic and the detail
// goes to the log, because an error string from this application can name a principal or a client.
export default function Error({ reset }: { error: Error; reset: () => void }) {
  return (
    <main className="min-h-screen flex items-center justify-center p-8">
      <div className="max-w-md text-center">
        <h1 className="text-2xl font-semibold text-mongodb-dark">Something went wrong</h1>
        <p className="mt-3 text-gray-600">The request could not be completed.</p>
        <button
          type="button"
          onClick={reset}
          className="mt-6 rounded-md bg-mongodb-dark px-4 py-2 text-white"
        >
          Try again
        </button>
      </div>
    </main>
  );
}
