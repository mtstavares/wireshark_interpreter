import { Navigate, Route, Routes } from "react-router";

import { AppShell } from "./components";
import { AboutPage } from "./pages/AboutPage";
import { AnalysisPage } from "./pages/AnalysisPage";
import { DashboardPage } from "./pages/DashboardPage";
import { UploadPage } from "./pages/UploadPage";

export default function App() {
  return (
    <AppShell>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/captures/new" element={<UploadPage />} />
        <Route path="/analyses/:analysisId" element={<AnalysisPage section="overview" />} />
        <Route path="/analyses/:analysisId/findings" element={<AnalysisPage section="findings" />} />
        <Route path="/analyses/:analysisId/network" element={<AnalysisPage section="network" />} />
        <Route path="/analyses/:analysisId/context" element={<AnalysisPage section="context" />} />
        <Route path="/analyses/:analysisId/timeline" element={<AnalysisPage section="timeline" />} />
        <Route path="/analyses/:analysisId/report" element={<AnalysisPage section="report" />} />
        <Route path="/about" element={<AboutPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppShell>
  );
}
