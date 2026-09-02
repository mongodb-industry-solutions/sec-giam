import { HelpTabs } from '../../../components/help/HelpTabs';

// Every help page carries the same tabs, so the section reads as one document rather than four pages.
export default function HelpLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="space-y-5">
      <HelpTabs />
      {children}
    </div>
  );
}
