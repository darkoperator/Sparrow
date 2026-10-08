import Accounts from "./accounts/Accounts";
import Share from "./share/Share";
import Shell from "./shell/Shell";
import Sql from "./sql/Sql";
import { Timeline } from "./timeline/Timeline";

export default function App() {
  // `canWrite` is false for a read-only case or before the analyst name is set: the timeline's writes follow it.
  return (
    <Shell
      screens={{
        timeline: (p) => <Timeline readOnly={!p.canWrite} />,
        accounts: (p) => <Accounts onSelect={p.showAccount} />,
        sql: () => <Sql />,
        share: (p) => <Share canImport={p.canWrite} onShowQueue={p.showQueue} />,
      }}
    />
  );
}
