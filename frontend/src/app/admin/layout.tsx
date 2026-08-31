export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 lg:h-screen lg:flex lg:flex-col lg:overflow-hidden">
      <main className="w-full max-w-5xl lg:max-w-none mx-auto px-3 sm:px-6 lg:px-10 py-4 sm:py-6 lg:flex-1 lg:min-h-0 lg:overflow-hidden">
        {children}
      </main>
    </div>
  );
}
