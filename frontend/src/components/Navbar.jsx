import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar() {
    const { user, logout, isAuthenticated } = useAuth();

    return (
        <nav className="navbar">
            <div className="navbar-content">
                <Link to="/" className="navbar-brand">
                    🔐 Secure Time Capsule
                </Link>

                <div className="navbar-menu">
                    {isAuthenticated ? (
                        <>
                            <Link to="/dashboard" className="navbar-link">Dashboard</Link>
                            <Link to="/create" className="navbar-link">Create Capsule</Link>
                            {user?.role === 'admin' && (
                                <Link to="/admin" className="navbar-link">Admin Panel</Link>
                            )}
                            {user?.role === 'auditor' && (
                                <Link to="/audit-logs" className="navbar-link">Audit Logs</Link>
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
