import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import RoleProtectedRoute from './components/RoleProtectedRoute';
import Home from './pages/Home';
import Register from './pages/Register';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import CreateCapsule from './pages/CreateCapsule';
import ViewCapsule from './pages/ViewCapsule';
import MFASetup from './pages/MFASetup';
import AdminDashboard from './pages/AdminDashboard';
import AuditorDashboard from './pages/AuditorDashboard';

function App() {
    return (
        <AuthProvider>
            <Router>
                <Navbar />
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/login" element={<Login />} />

                    {/* User Dashboard */}
                    <Route path="/dashboard" element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    } />

                    {/* Admin Dashboard - Admin only */}
                    <Route path="/admin" element={
                        <RoleProtectedRoute allowedRoles={['admin']}>
                            <AdminDashboard />
                        </RoleProtectedRoute>
                    } />

                    {/* Auditor Dashboard - Auditor only */}
                    <Route path="/audit" element={
                        <RoleProtectedRoute allowedRoles={['auditor']}>
                            <AuditorDashboard />
                        </RoleProtectedRoute>
                    } />

                    {/* Capsule routes - User only */}
                    <Route path="/create" element={
                        <RoleProtectedRoute allowedRoles={['user']}>
                            <CreateCapsule />
                        </RoleProtectedRoute>
                    } />

                    <Route path="/capsule/:id" element={
                        <RoleProtectedRoute allowedRoles={['user']}>
                            <ViewCapsule />
                        </RoleProtectedRoute>
                    } />

                    <Route path="/mfa-setup" element={<MFASetup />} />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
