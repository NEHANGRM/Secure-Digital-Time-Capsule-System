/**
 * ADMIN DASHBOARD
 * 
 * SECURITY: Only accessible by admin role
 * Features:
 * - User management (view all users, change roles)
 * - System statistics
 * - Capsule metadata (NO content access)
 */

import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

export default function AdminDashboard() {
    const { user } = useAuth();
    const [activeTab, setActiveTab] = useState('stats');
    const [users, setUsers] = useState([]);
    const [capsules, setCapsules] = useState([]);
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    useEffect(() => {
        loadData();
    }, [activeTab]);

    const loadData = async () => {
        setLoading(true);
        setError('');
        try {
            if (activeTab === 'stats') {
                const response = await api.get('/admin/stats');
                setStats(response.data.stats);
            } else if (activeTab === 'users') {
                const response = await api.get('/admin/users');
                setUsers(response.data.users);
            } else if (activeTab === 'capsules') {
                const response = await api.get('/admin/capsules');
                setCapsules(response.data.capsules);
            }
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to load data');
        } finally {
            setLoading(false);
        }
    };

    const changeUserRole = async (userId, newRole) => {
        try {
            setError('');
            setSuccess('');
            await api.put(`/admin/users/${userId}/role`, { role: newRole });
            setSuccess('Role updated successfully!');
            loadData();
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to update role');
        }
    };

    const renderStats = () => (
        <div className="stats-grid">
            <div className="stat-card">
                <div className="stat-icon">👥</div>
                <div className="stat-value">{stats?.totalUsers || 0}</div>
                <div className="stat-label">Total Users</div>
            </div>
            <div className="stat-card">
                <div className="stat-icon">📦</div>
                <div className="stat-value">{stats?.totalCapsules || 0}</div>
                <div className="stat-label">Total Capsules</div>
            </div>
            <div className="stat-card">
                <div className="stat-icon">🔒</div>
                <div className="stat-value">{stats?.lockedCapsules || 0}</div>
                <div className="stat-label">Locked Capsules</div>
            </div>
            <div className="stat-card">
                <div className="stat-icon">🔓</div>
                <div className="stat-value">{stats?.unlockedCapsules || 0}</div>
                <div className="stat-label">Unlocked Capsules</div>
            </div>
        </div>
    );

    const renderUsers = () => (
        <div className="table-container">
            <table className="data-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>MFA Enabled</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {users.map(u => (
                        <tr key={u._id}>
                            <td>{u.username}</td>
                            <td>{u.email}</td>
                            <td>
                                <span className={`role-badge role-${u.role}`}>
                                    {u.role}
                                </span>
                            </td>
                            <td>{u.mfaEnabled ? '✅' : '❌'}</td>
                            <td>{new Date(u.createdAt).toLocaleDateString()}</td>
                            <td>
                                <select
                                    value={u.role}
                                    onChange={(e) => changeUserRole(u._id, e.target.value)}
                                    disabled={u._id === user._id}
                                    className="role-select"
                                >
                                    <option value="user">User</option>
                                    <option value="admin">Admin</option>
                                    <option value="auditor">Auditor</option>
                                </select>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );

    const renderCapsules = () => (
        <div className="table-container">
            <div className="alert alert-warning" style={{ marginBottom: '1rem' }}>
                ⚠️ <strong>Metadata Only:</strong> Admins cannot access capsule content to ensure user privacy.
            </div>
            <table className="data-table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Owner</th>
                        <th>Type</th>
                        <th>Unlock Date</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    {capsules.map(c => (
                        <tr key={c._id}>
                            <td>{c.title}</td>
                            <td>{c.owner?.email || 'Unknown'}</td>
                            <td><span className="type-badge">{c.type}</span></td>
                            <td>{new Date(c.unlockDate).toLocaleDateString()}</td>
                            <td>{new Date(c.createdAt).toLocaleDateString()}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );

    return (
        <div className="admin-dashboard">
            <div className="container">
                <div className="page-header">
                    <h1>🛡️ Admin Dashboard</h1>
                    <p>Manage users, view statistics, and monitor capsule metadata</p>
                </div>

                <nav className="dashboard-nav">
                    <button
                        className={`nav-btn ${activeTab === 'stats' ? 'active' : ''}`}
                        onClick={() => setActiveTab('stats')}
                    >
                        📊 Statistics
                    </button>
                    <button
                        className={`nav-btn ${activeTab === 'users' ? 'active' : ''}`}
                        onClick={() => setActiveTab('users')}
                    >
                        👥 User Management
                    </button>
                    <button
                        className={`nav-btn ${activeTab === 'capsules' ? 'active' : ''}`}
                        onClick={() => setActiveTab('capsules')}
                    >
                        📦 Capsule Metadata
                    </button>
                </nav>

                <main className="dashboard-main">
                    {error && <div className="alert alert-error">{error}</div>}
                    {success && <div className="alert alert-success">{success}</div>}

                    {loading ? (
                        <div className="flex-center" style={{ padding: '3rem' }}>
                            <div className="spinner"></div>
                        </div>
                    ) : (
                        <>
                            {activeTab === 'stats' && renderStats()}
                            {activeTab === 'users' && renderUsers()}
                            {activeTab === 'capsules' && renderCapsules()}
                        </>
                    )}
                </main>
            </div>

            <style>{`
                .admin-dashboard {
                    padding: 2rem 0;
                }
                .page-header {
                    margin-bottom: 2rem;
                }
                .page-header h1 {
                    margin-bottom: 0.5rem;
                }
                .page-header p {
                    color: var(--text-secondary);
                }
                .dashboard-nav {
                    background: var(--bg-secondary);
                    padding: 1rem;
                    display: flex;
                    gap: 0.75rem;
                    justify-content: center;
                    border-radius: 12px;
                    margin-bottom: 2rem;
                }
                .nav-btn {
                    padding: 0.75rem 1.5rem;
                    border: none;
                    background: transparent;
                    color: var(--text-secondary);
                    cursor: pointer;
                    border-radius: 8px;
                    font-size: 1rem;
                    transition: all 0.2s;
                }
                .nav-btn:hover {
                    background: var(--bg-tertiary);
                    color: var(--text-primary);
                }
                .nav-btn.active {
                    background: var(--accent-primary);
                    color: white;
                }
                .dashboard-main {
                    min-height: 400px;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1.5rem;
                }
                .stat-card {
                    background: var(--bg-secondary);
                    padding: 2rem;
                    border-radius: 12px;
                    text-align: center;
                    border: 1px solid var(--border-color);
                    transition: transform 0.2s, box-shadow 0.2s;
                }
                .stat-card:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 25px rgba(0,0,0,0.3);
                }
                .stat-icon {
                    font-size: 2.5rem;
                    margin-bottom: 0.5rem;
                }
                .stat-value {
                    font-size: 2.5rem;
                    font-weight: bold;
                    color: var(--accent-primary);
                }
                .stat-label {
                    color: var(--text-secondary);
                    margin-top: 0.5rem;
                }
                .table-container {
                    overflow-x: auto;
                    background: var(--bg-secondary);
                    border-radius: 12px;
                    padding: 1rem;
                }
                .data-table {
                    width: 100%;
                    border-collapse: collapse;
                }
                .data-table th, .data-table td {
                    padding: 1rem;
                    text-align: left;
                    border-bottom: 1px solid var(--border-color);
                }
                .data-table th {
                    background: var(--bg-tertiary);
                    font-weight: 600;
                    color: var(--text-primary);
                }
                .data-table th:first-child {
                    border-radius: 8px 0 0 0;
                }
                .data-table th:last-child {
                    border-radius: 0 8px 0 0;
                }
                .data-table tr:hover td {
                    background: var(--bg-tertiary);
                }
                .data-table tr:last-child td {
                    border-bottom: none;
                }
                .role-badge {
                    display: inline-block;
                    padding: 0.25rem 0.75rem;
                    border-radius: 20px;
                    font-size: 0.85rem;
                    font-weight: 500;
                    text-transform: capitalize;
                }
                .role-user { background: #10b981; color: white; }
                .role-admin { background: #8b5cf6; color: white; }
                .role-auditor { background: #f59e0b; color: white; }
                .type-badge {
                    display: inline-block;
                    padding: 0.25rem 0.5rem;
                    background: var(--bg-tertiary);
                    border-radius: 4px;
                    font-size: 0.85rem;
                    text-transform: capitalize;
                }
                .role-select {
                    padding: 0.5rem 1rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    background: var(--bg-primary);
                    color: var(--text-primary);
                    cursor: pointer;
                    min-width: 100px;
                }
                .role-select:disabled {
                    opacity: 0.5;
                    cursor: not-allowed;
                }
                .alert-warning {
                    background: rgba(245, 158, 11, 0.1);
                    border: 1px solid #f59e0b;
                    color: #f59e0b;
                    padding: 1rem;
                    border-radius: 8px;
                }
            `}</style>
        </div>
    );
}

