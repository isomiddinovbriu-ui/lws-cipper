import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import HomePage from './pages/HomePage';
import EncryptPage from './pages/EncryptPage';
import DecryptPage from './pages/DecryptPage';
import BenchmarkPage from './pages/BenchmarkPage';
import AlgorithmsPage from './pages/AlgorithmsPage';
import RealtimeBenchmarkPage from './pages/RealtimeBenchmarkPage';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/encrypt" element={<EncryptPage />} />
        <Route path="/decrypt" element={<DecryptPage />} />
        <Route path="/benchmark" element={<BenchmarkPage />} />
        <Route path="/realtime" element={<RealtimeBenchmarkPage />} />
        <Route path="/algorithms" element={<AlgorithmsPage />} />
      </Routes>
    </Layout>
  );
}
