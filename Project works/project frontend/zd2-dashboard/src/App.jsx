import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

import Sidebar from "./components/layout/Sidebar";
import Topbar from "./components/layout/Topbar";

import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AttackEvents from "./pages/AttackEvents";
import Hosts from "./pages/Hosts";
import SourceIPs from "./pages/SourceIPs";
import ThreatHunting from "./pages/ThreatHunting";
import Analytics from "./pages/Analytics";
import Settings from "./pages/Settings";
import Profile from "./pages/Profile";


function App() {

  return (

    <BrowserRouter>

      <div className="min-h-screen bg-slate-950 text-white flex">

        {/* SIDEBAR */}

        <Sidebar />


        {/* MAIN AREA */}

        <main className="flex-1">

          {/* TOPBAR */}

          <Topbar />


          {/* PAGE CONTENT */}

          <Routes>

            <Route
              path="/"
              element={
                <Navigate
                  to="/dashboard"
                  replace
                />
              }
            />

            <Route
              path="/dashboard"
              element={<Dashboard />}
            />


            <Route
              path="/alerts"
              element={<Alerts />}
            />

            <Route
              path="/attack-events"
              element={<AttackEvents />}
            />

            <Route
              path="/hosts"
              element={<Hosts />}
            />

            <Route
              path="/source-ips"
              element={<SourceIPs />}
            />

            <Route
              path="/threat-hunting"
              element={<ThreatHunting />}
            />

            <Route
              path="/analytics"
              element={<Analytics />}
            />

            <Route
              path="/settings"
              element={<Settings />}
            />

            <Route
              path="/profile"
              element={<Profile />}
            />

          </Routes>

        </main>

      </div>

    </BrowserRouter>

  );

}

export default App;