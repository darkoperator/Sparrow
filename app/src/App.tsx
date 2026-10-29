import Accounts from "./accounts/Accounts";
import Devices from "./devices/Devices";
import EntityTab from "./entity/EntityTab";
import EventsView from "./events/EventsView";
import Share from "./share/Share";
import Shell from "./shell/Shell";
import Sql from "./sql/Sql";
import { Timeline } from "./timeline/Timeline";

export default function App() {
  // `canWrite` is false for a read-only case or before the analyst name is set: the timeline's writes follow it.
  return (
    <Shell
      entityTab={(e, p) => <EntityTab entity={e} canWrite={p.canWrite} />}
      screens={{
        events: (p) => <EventsView chip={p.eventsEntity ?? undefined} onClearChip={p.clearEventsEntity} />,
        timeline: (p) => <Timeline readOnly={!p.canWrite} />,
        accounts: (p) => <Accounts onSelect={p.showAccount} />,
        devices: () => <Devices />,
        sql: () => <Sql />,
        share: (p) => <Share canImport={p.canWrite} onShowQueue={p.showQueue} />,
      }}
    />
  );
}
