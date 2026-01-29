import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Navbar from './components/Navbar';
import ProtectedRoute from './components/ProtectedRoute';
import Home from './pages/Home';
import Register from './pages/Register';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import CreateCapsule from './pages/CreateCapsule';
import ViewCapsule from './pages/ViewCapsule';
import MFASetup from './pages/MFASetup';

function App() {
    return (
        <AuthProvider>
            <Router>
                <Navbar />
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/login" element={<Login />} />

                    <Route path="/dashboard" element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    } />

                    <Route path="/create" element={
                        <ProtectedRoute>
                            <CreateCapsule />
                        </ProtectedRoute>
                    } />

                    <Route path="/capsule/:id" element={
                        <ProtectedRoute>
                            <ViewCapsule />
                        </ProtectedRoute>
                    } />

                    <Route path="/mfa-setup" element={
                        <ProtectedRoute>
                            <MFASetup />
                        </ProtectedRoute>
                    } />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
