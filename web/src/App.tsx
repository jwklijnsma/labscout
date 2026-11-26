import { Login, Toasts, TopBar } from "./components/Chrome";
import { HostsPage } from "./components/HostsPage";
import { JobsPanel } from "./components/JobsPanel";
import { PlanPage } from "./components/PlanPage";
import { ScanPage } from "./components/ScanPage";
import { Sidebar } from "./components/Sidebar";
import { AppProvider, useApp, useRoute } from "./store";

function Shell() {
  const { authed } = useApp();
  const { page, ip } = useRoute();

  if (authed === null) return null;
  if (!authed) {
    return (
      <>
        <header className="topbar"><div className="brand"><img src="/favicon.svg" alt="" /> labscout</div></header>
        <Login />
      </>
    );
  }
  return (
    <>
      <TopBar />
      <div className="layout">
        <Sidebar page={page} />
        <main>
          {page === "hosts" && <HostsPage ip={ip} />}
          {page === "plan" && <PlanPage />}
          {page === "scan" && <ScanPage />}
        </main>
      </div>
      <JobsPanel />
      <Toasts />
    </>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
