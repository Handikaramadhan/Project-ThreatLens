import { Bell } from "lucide-react";
import { EmptyState } from "../ui/EmptyState";
import { Panel } from "../ui/Panel";

export function AlertsView() {
  return (
    <section className="view-grid">
      <Panel title="Alert Queue" icon={<Bell size={18} />} wide>
        <EmptyState icon={<Bell size={24} />} text="Belum ada alert tercatat." />
      </Panel>
    </section>
  );
}
