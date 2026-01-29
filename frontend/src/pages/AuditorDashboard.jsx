/**
 * AUDITOR DASHBOARD
 * 
 * SECURITY: Only accessible by auditor role
 * Features:
 * - View all audit logs
 * - Filter by action type
 * - Search by user
 */

import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';

export default function AuditorDashboard() {
    const { user } = useAuth();
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');
    const [filter, setFilter] = useState({
        action: '',
        limit: 100
    });

    const actionTypes = [
        'LOGIN', 'REGISTER', 'LOGOUT',
        'MFA_SETUP', 'MFA_VERIFY', 'FAILED_MFA', 'MFA_ENABLED',
        'CAPSULE_CREATE', 'CAPSULE_READ', 'CAPSULE_DELETE',
        'ROLE_CHANGE', 'INTEGRITY_VIOLATION'
    ];

    useEffect(() => {
        loadLogs();
    }, [filter]);

    const loadLogs = async () => {
        setLoading(true);
        setError('');
        try {
            const params = new URLSearchParams();
            if (filter.action) params.append('action', filter.action);
            if (filter.limit) params.append('limit', filter.limit);

            const response = await api.get(`/admin/audit-logs?${params.toString()}`);
            setLogs(response.data.logs);
        } catch (err) {
            setError(err.response?.data?.message || 'Failed to load audit logs');
        } finally {
            setLoading(false);
        }
    };

    const getActionColor = (action) => {
        const colors = {
            'LOGIN': '#10b981',
            'REGISTER': '#3b82f6',
            'LOGOUT': '#6b7280',
            'MFA_SETUP': '#8b5cf6',
            'MFA_VERIFY': '#10b981',
            'MFA_ENABLED': '#22c55e',
            'FAILED_MFA': '#ef4444',
            'CAPSULE_CREATE': '#06b6d4',
            'CAPSULE_READ': '#14b8a6',
            'CAPSULE_DELETE': '#f59e0b',
            'ROLE_CHANGE': '#ec4899',
            'INTEGRITY_VIOLATION': '#dc2626'
        };
        return colors[action] || '#6b7280';
    };

    const getStatusIcon = (status) => {
        if (status === 'FAILURE') return '❌';
        if (status === 'SUCCESS') return '✅';
        return '📝';
    };

    return (
        <div className="auditor-dashboard">
            <div className="container">
                <div className="page-header">
                    <h1>📋 Audit Dashboard</h1>
                    <p>Monitor and review all system activity logs</p>
                </div>

                <div className="filter-bar">
                    <div className="filter-group">
                        <label>Filter by Action:</label>
                        <select
                            value={filter.action}
                            onChange={(e) => setFilter({ ...filter, action: e.target.value })}
                        >
                            <option value="">All Actions</option>
                            {actionTypes.map(action => (
                                <option key={action} value={action}>{action}</option>
                            ))}
                        </select>
                    </div>
                    <div className="filter-group">
                        <label>Limit:</label>
                        <select
                            value={filter.limit}
                            onChange={(e) => setFilter({ ...filter, limit: e.target.value })}
                        >
                            <option value="50">50</option>
                            <option value="100">100</option>
                            <option value="250">250</option>
                            <option value="500">500</option>
                        </select>
                    </div>
                    <button onClick={loadLogs} className="btn btn-primary">
                        🔄 Refresh
                    </button>
                </div>

                {error && <div className="alert alert-error">{error}</div>}

                {loading ? (
                    <div className="flex-center" style={{ padding: '3rem' }}>
                        <div className="spinner"></div>
                    </div>
                ) : (
                    <div className="logs-container">
                        <div className="logs-header">
                            <span>Showing {logs.length} audit entries</span>
                        </div>
                        <div className="logs-list">
                            {logs.length === 0 ? (
                                <div className="no-logs">
                                    <p>No audit logs found</p>
                                </div>
                            ) : (
                                logs.map(log => (
                                    <div key={log._id} className="log-entry">
                                        <div className="log-icon">
                                            {getStatusIcon(log.status)}
                                        </div>
                                        <div className="log-content">
                                            <div className="log-header">
                                                <span
                                                    className="action-badge"
                                                    style={{ backgroundColor: getActionColor(log.action) }}
                                                >
                                                    {log.action}
                                                </span>
                                                <span className="log-time">
                                                    {new Date(log.createdAt).toLocaleString()}
                                                </span>
                                            </div>
                                            <div className="log-details">
                                                <strong>{log.user?.username || 'Unknown User'}</strong>
                                                <span>{log.user?.email}</span>
                                            </div>
                                            <div className="log-message">
                                                {log.details}
                                            </div>
                                            <div className="log-meta">
                                                <span>IP: {log.ipAddress || 'N/A'}</span>
                                                <span>Role: {log.user?.role || 'N/A'}</span>
                                            </div>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                )}
            </div>

            <style>{`
                .auditor-dashboard {
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
                .filter-bar {
                    background: var(--bg-secondary);
                    padding: 1rem 1.5rem;
                    border-radius: 12px;
                    display: flex;
                    gap: 1.5rem;
                    align-items: center;
                    margin-bottom: 1.5rem;
                    flex-wrap: wrap;
                }
                .filter-group {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }
                .filter-group label {
                    color: var(--text-secondary);
                    font-size: 0.9rem;
                }
                .filter-group select {
                    padding: 0.5rem 1rem;
                    border-radius: 6px;
                    border: 1px solid var(--border-color);
                    background: var(--bg-primary);
                    color: var(--text-primary);
                    cursor: pointer;
                }
                .logs-container {
                    background: var(--bg-secondary);
                    border-radius: 12px;
                    overflow: hidden;
                }
                .logs-header {
                    padding: 1rem 1.5rem;
                    background: var(--bg-tertiary);
                    border-bottom: 1px solid var(--border-color);
                    color: var(--text-secondary);
                    font-weight: 500;
                }
                .logs-list {
                    max-height: 60vh;
                    overflow-y: auto;
                }
                .no-logs {
                    padding: 3rem;
                    text-align: center;
                    color: var(--text-secondary);
                }
                .log-entry {
                    display: flex;
                    gap: 1rem;
                    padding: 1rem 1.5rem;
                    border-bottom: 1px solid var(--border-color);
                    transition: background 0.2s;
                }
                .log-entry:last-child {
                    border-bottom: none;
                }
                .log-entry:hover {
                    background: var(--bg-tertiary);
                }
                .log-icon {
                    font-size: 1.25rem;
                    padding-top: 0.25rem;
                }
                .log-content {
                    flex: 1;
                    min-width: 0;
                }
                .log-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 0.5rem;
                    flex-wrap: wrap;
                    gap: 0.5rem;
                }
                .action-badge {
                    display: inline-block;
                    padding: 0.25rem 0.75rem;
                    border-radius: 20px;
                    font-size: 0.75rem;
                    font-weight: 600;
                    color: white;
                }
                .log-time {
                    font-size: 0.85rem;
                    color: var(--text-secondary);
                }
                .log-details {
                    display: flex;
                    gap: 1rem;
                    margin-bottom: 0.5rem;
                    flex-wrap: wrap;
                }
                .log-details strong {
                    color: var(--text-primary);
                }
                .log-details span {
                    color: var(--text-secondary);
                    font-size: 0.9rem;
                }
                .log-message {
                    color: var(--text-primary);
                    margin-bottom: 0.5rem;
                    word-break: break-word;
                }
                .log-meta {
                    display: flex;
                    gap: 1.5rem;
                    font-size: 0.8rem;
                    color: var(--text-secondary);
                }
            `}</style>
        </div>
    );
}

