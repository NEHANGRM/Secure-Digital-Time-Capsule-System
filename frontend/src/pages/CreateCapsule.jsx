import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';

export default function CreateCapsule() {
    const navigate = useNavigate();
    const [formData, setFormData] = useState({
        title: '',
        content: '',
        unlockDate: ''
    });
    const [file, setFile] = useState(null);
    const [filePreview, setFilePreview] = useState(null);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [loading, setLoading] = useState(false);
    const [dragActive, setDragActive] = useState(false);

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleFileChange = (e) => {
        const selectedFile = e.target.files[0];
        processFile(selectedFile);
    };

    const processFile = (selectedFile) => {
        if (selectedFile) {
            // Validate file size (max 10MB)
            if (selectedFile.size > 10 * 1024 * 1024) {
                setError('File size must be less than 10MB');
                return;
            }

            // Validate file type
            const allowedTypes = [
                'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
                'video/mp4', 'video/webm', 'video/quicktime',
                'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain'
            ];

            if (!allowedTypes.includes(selectedFile.type)) {
                setError('Invalid file type. Supported: images, videos (mp4, webm, mov), PDF, DOC, DOCX, TXT');
                return;
            }

            setFile(selectedFile);
            setError('');

            // Create preview for images
            if (selectedFile.type.startsWith('image/')) {
                const reader = new FileReader();
                reader.onloadend = () => {
                    setFilePreview(reader.result);
                };
                reader.readAsDataURL(selectedFile);
            } else {
                setFilePreview(null);
            }
        }
    };

    const handleDrag = (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setDragActive(true);
        } else if (e.type === 'dragleave') {
            setDragActive(false);
        }
    };

    const handleDrop = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            processFile(e.dataTransfer.files[0]);
        }
    };

    const removeFile = () => {
        setFile(null);
        setFilePreview(null);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setSuccess('');

        // Validate unlock date is at least 3 minutes in the future
        const unlockDate = new Date(formData.unlockDate);
        const now = new Date();
        const minTime = new Date(now.getTime() + 3 * 60 * 1000); // 3 minutes from now

        if (unlockDate < minTime) {
            setError('Unlock date must be at least 3 minutes in the future');
            return;
        }

        setLoading(true);

        try {
            let requestData;
            let contentType = 'application/json';

            if (file) {
                // Create FormData for file upload
                const formDataToSend = new FormData();
                formDataToSend.append('title', formData.title);
                formDataToSend.append('content', formData.content || `File: ${file.name}`);
                formDataToSend.append('unlockDate', formData.unlockDate);
                formDataToSend.append('type', 'file');
                formDataToSend.append('file', file);
                formDataToSend.append('fileName', file.name);
                formDataToSend.append('fileType', file.type);

                requestData = formDataToSend;
                contentType = 'multipart/form-data';
            } else {
                // Text-only capsule
                requestData = {
                    title: formData.title,
                    content: formData.content,
                    unlockDate: formData.unlockDate,
                    type: 'text'
                };
            }

            const response = await api.post('/capsules/create', requestData, {
                headers: contentType === 'multipart/form-data' ? {} : { 'Content-Type': 'application/json' }
            });

            setSuccess('Time capsule created successfully! Redirecting...');
            setTimeout(() => {
                navigate('/dashboard');
            }, 2000);

        } catch (err) {
            setError(err.response?.data?.message || 'Failed to create capsule');
        } finally {
            setLoading(false);
        }
    };

    // Get minimum datetime (3 minutes from now)
    const getMinDateTime = () => {
        const minTime = new Date();
        minTime.setMinutes(minTime.getMinutes() + 3);
        return minTime.toISOString().slice(0, 16);
    };

    const getFileIcon = () => {
        if (!file) return '';
        if (file.type.startsWith('image/')) return '🖼️';
        if (file.type.startsWith('video/')) return '🎥';
        if (file.type === 'application/pdf') return '📄';
        if (file.type.includes('document') || file.type.includes('word')) return '📝';
        return '📎';
    };

    return (
        <div className="container" style={{ maxWidth: '700px', marginTop: '2rem' }}>
            <div className="card">
                <h1>Create Time Capsule</h1>
                <p style={{ marginBottom: '2rem' }}>
                    Store an encrypted message or file that will unlock at a future date
                </p>

                {error && <div className="alert alert-error">{error}</div>}
                {success && <div className="alert alert-success">{success}</div>}

                <form onSubmit={handleSubmit}>
                    <div className="form-group">
                        <label htmlFor="title">Capsule Title</label>
                        <input
                            type="text"
                            id="title"
                            name="title"
                            value={formData.title}
                            onChange={handleChange}
                            required
                            placeholder="e.g., My 2027 Memories"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="content">Message Content</label>
                        <textarea
                            id="content"
                            name="content"
                            value={formData.content}
                            onChange={handleChange}
                            required={!file}
                            placeholder="Write your message here... This will be securely encrypted"
                            rows={file ? 4 : 8}
                        />
                        <small style={{ color: 'var(--text-muted)' }}>
                            {file ? 'Optional message to accompany your file' : 'Your message will be encrypted and secured until the unlock date.'}
                        </small>
                    </div>

                    {/* File Upload Section */}
                    <div className="form-group">
                        <label>Attach File (Optional)</label>
                        <div
                            className={`file-upload-zone ${dragActive ? 'drag-active' : ''}`}
                            onDragEnter={handleDrag}
                            onDragLeave={handleDrag}
                            onDragOver={handleDrag}
                            onDrop={handleDrop}
                            style={{
                                border: `2px dashed ${dragActive ? 'var(--accent-primary)' : 'var(--border-color)'}`,
                                borderRadius: '8px',
                                padding: '2rem',
                                textAlign: 'center',
                                cursor: 'pointer',
                                transition: 'all 0.3s ease',
                                backgroundColor: dragActive ? 'rgba(139, 92, 246, 0.05)' : 'transparent'
                            }}
                            onClick={() => !file && document.getElementById('fileInput').click()}
                        >
                            {!file ? (
                                <>
                                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📎</div>
                                    <p style={{ marginBottom: '0.5rem', fontWeight: 500 }}>
                                        Drag and drop a file here, or click to browse
                                    </p>
                                    <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                                        Supported: Images, Videos (mp4, webm, mov), PDF, DOC, TXT
                                    </p>
                                    <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                                        Max file size: 10MB
                                    </p>
                                </>
                            ) : (
                                <div>
                                    {filePreview && (
                                        <img
                                            src={filePreview}
                                            alt="Preview"
                                            style={{
                                                maxWidth: '200px',
                                                maxHeight: '200px',
                                                borderRadius: '8px',
                                                marginBottom: '1rem'
                                            }}
                                        />
                                    )}
                                    <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>
                                        {getFileIcon()}
                                    </div>
                                    <p style={{ fontWeight: 500, marginBottom: '0.25rem' }}>
                                        {file.name}
                                    </p>
                                    <p style={{ fontSize: '0.875rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>
                                        {(file.size / 1024).toFixed(2)} KB
                                    </p>
                                    <button
                                        type="button"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            removeFile();
                                        }}
                                        className="btn btn-secondary"
                                        style={{ fontSize: '0.875rem', padding: '0.5rem 1rem' }}
                                    >
                                        Remove File
                                    </button>
                                </div>
                            )}
                        </div>
                        <input
                            type="file"
                            id="fileInput"
                            onChange={handleFileChange}
                            style={{ display: 'none' }}
                            accept="image/*,video/mp4,video/webm,video/quicktime,application/pdf,.doc,.docx,text/plain"
                        />
                    </div>

                    <div className="form-group">
                        <label htmlFor="unlockDate">Unlock Date & Time</label>
                        <input
                            type="datetime-local"
                            id="unlockDate"
                            name="unlockDate"
                            value={formData.unlockDate}
                            onChange={handleChange}
                            required
                            min={getMinDateTime()}
                        />
                        <small style={{ color: 'var(--text-muted)' }}>
                            Minimum: 3 minutes from now. The capsule will unlock after this time.
                        </small>
                    </div>

                    <div className="alert alert-info">
                        <strong>🔒 Your capsule will be:</strong>
                        <ul style={{ marginTop: '0.5rem', marginLeft: '1.5rem', marginBottom: 0 }}>
                            <li>Encrypted with military-grade security (ECC P-256)</li>
                            <li>Protected with digital signatures</li>
                            <li>Time-locked until your chosen date</li>
                            {file && <li>File encrypted and securely stored</li>}
                        </ul>
                    </div>

                    <div className="flex gap-1">
                        <button
                            type="button"
                            onClick={() => navigate('/dashboard')}
                            className="btn btn-secondary"
                            style={{ flex: 1 }}
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            className="btn btn-primary"
                            disabled={loading}
                            style={{ flex: 1 }}
                        >
                            {loading ? 'Creating...' : 'Create Capsule'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
