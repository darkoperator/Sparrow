import { displaySafe } from "../text";

/** Shown while a case is open read-only; every write control is disabled and the backend refuses writes too. */
export default function ReadOnlyBanner({ reason }: { reason: string }) {
  return (
    <div role="status" className="banner banner-readonly">
      <strong>Read-only.</strong> {displaySafe(reason)}
    </div>
  );
}
