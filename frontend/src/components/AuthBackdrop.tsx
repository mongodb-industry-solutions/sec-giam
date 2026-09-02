/**
 * The page behind every credential screen.
 *
 * Sign-in, consent, registration and sign-out all sit on the platform's dark field rather than on
 * white, so the screen a relying party redirects to is recognisably part of the same product as the
 * portal a person came from. The panel keeps its own white card: contrast is what makes a credential
 * form legible, and the backdrop is decoration behind it, marked as such for a screen reader.
 */
export function AuthBackdrop({ children }: { children: React.ReactNode }) {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#001E2B] p-4 sm:p-8">
      <div aria-hidden className="auth-backdrop pointer-events-none absolute inset-0" />
      <div className="relative z-10 flex w-full flex-col items-center">{children}</div>
    </main>
  );
}

export default AuthBackdrop;
