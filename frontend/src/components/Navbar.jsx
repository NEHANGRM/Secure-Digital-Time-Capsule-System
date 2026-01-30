import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
    const { user, logout, isAuthenticated } = useAuth();
    const location = useLocation();

    // Hide entire navbar on home/login/register/mfa pages
    const hideNavbar = ['/', '/login', '/register', '/mfa-setup'].includes(location.pathname);

    // Determine the correct dashboard link based on role
    const getDashboardLink = () => {
        if (user?.role === 'admin') return '/admin';
        if (user?.role === 'auditor') return '/audit';
        return '/dashboard';
    };

    const getDashboardLabel = () => {
        if (user?.role === 'admin') return 'Admin Panel';
        if (user?.role === 'auditor') return 'Audit Logs';
        return 'Dashboard';
    };

    // Don't render navbar at all on home/auth pages
    if (hideNavbar) {
        return null;
    }

    return (
        <nav className="navbar">
            <div className="navbar-content">
                <Link to="/" className="navbar-brand">
                    🔐 Secure Time Capsule
                </Link>

                <div className="navbar-menu">
                    {isAuthenticated ? (
                        <>
                            <Link to={getDashboardLink()} className="navbar-link">
                                {getDashboardLabel()}
                            </Link>

                            {/* Only show Create Capsule for regular users */}
                            {user?.role === 'user' && (
                                <Link to="/create" className="navbar-link">Create Capsule</Link>
                            )}

                            <span className={`badge badge-${user?.role}`}>{user?.role}</span>
                            <span className="navbar-link">{user?.username}</span>
                            <button onClick={logout} className="btn btn-secondary">Logout</button>
                        </>
                    ) : (
                        <>
                            <Link to="/login" className="navbar-link">Login</Link>
                            <Link to="/register" className="btn btn-primary">Register</Link>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
}
