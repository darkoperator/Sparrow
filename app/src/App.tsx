import Shell from "./shell/Shell";
import { Timeline } from "./timeline/Timeline";

export default function App() {
  // `canWrite` is false for a read-only case or before the analyst name is set: the timeline's writes follow it.
  return <Shell screens={{ timeline: (p) => <Timeline readOnly={!p.canWrite} /> }} />;
}
