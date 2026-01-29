/**
 * ROLE-PROTECTED ROUTE COMPONENT
 * 
 * Restricts access to routes based on user role
 */

import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function RoleProtectedRoute({ children, allowedRoles }) {
    const { user, isAuthenticated, loading } = useAuth();

    if (loading) {
        return (
            <div className="flex-center" style={{ minHeight: '100vh' }}>
                <div className="spinner"></div>
            </div>
        );
    }

    // Not logged in
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    // Check role
    if (!allowedRoles.includes(user?.role)) {
        // Redirect to appropriate dashboard based on role
        if (user?.role === 'admin') {
            return <Navigate to="/admin" replace />;
        } else if (user?.role === 'auditor') {
            return <Navigate to="/audit" replace />;
        } else {
            return <Navigate to="/dashboard" replace />;
        }
    }

    return children;
}
