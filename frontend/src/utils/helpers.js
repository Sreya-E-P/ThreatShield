import { format, formatDistance } from 'date-fns';

export const formatDate = (date, formatStr = 'PPpp') => { if (!date) return 'N/A'; try { return format(new Date(date), formatStr); } catch { return 'Invalid date'; } };
export const formatRelativeTime = (date) => { if (!date) return 'N/A'; try { return formatDistance(new Date(date), new Date(), { addSuffix: true }); } catch { return 'Invalid date'; } };
export const formatBytes = (bytes, decimals = 2) => { if (bytes === 0) return '0 Bytes'; const k = 1024; const dm = decimals < 0 ? 0 : decimals; const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i]; };
export const formatNumber = (num, decimals = 0) => { if (num === null || num === undefined) return 'N/A'; return num.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }); };
export const truncateString = (str, length = 50) => { if (!str) return ''; if (str.length <= length) return str; return str.substring(0, length) + '...'; };
export const getSeverityColor = (severity) => ({ critical: '#f44336', high: '#ff9800', medium: '#ffeb3b', low: '#4caf50', info: '#2196f3' }[severity] || '#9e9e9e');
export const getRiskLevel = (score) => { if (score >= 0.8) return 'critical'; if (score >= 0.6) return 'high'; if (score >= 0.3) return 'medium'; return 'low'; };
export const downloadBlob = (blob, filename) => { const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url); };
export const copyToClipboard = async (text) => { try { await navigator.clipboard.writeText(text); return true; } catch { return false; } };