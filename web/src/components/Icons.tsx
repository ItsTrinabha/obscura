type P = { size?: number };
const svg = (size: number, children: React.ReactNode) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {children}
  </svg>
);

export const Shield = ({ size = 18 }: P) => svg(size, <><path d="M12 2 4 5v6c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5z" /><circle cx="12" cy="11" r="2" /><path d="M12 13v3" /></>);
export const ShieldCheck = ({ size = 18 }: P) => svg(size, <><path d="M12 2 4 5v6c0 5.2 3.4 9.7 8 11 4.6-1.3 8-5.8 8-11V5z" /><path d="m9 12 2 2 4-4" /></>);
export const Lock = ({ size = 14 }: P) => svg(size, <><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>);
export const Paperclip = ({ size = 20 }: P) => svg(size, <path d="m21 11-8.6 8.6a5.5 5.5 0 0 1-7.8-7.8l8.6-8.6a3.7 3.7 0 0 1 5.2 5.2l-8.6 8.6a1.8 1.8 0 0 1-2.6-2.6L15 6.6" />);
export const Send = ({ size = 20 }: P) => svg(size, <><path d="m22 2-7 20-4-9-9-4z" /><path d="M22 2 11 13" /></>);
export const Plus = ({ size = 18 }: P) => svg(size, <><path d="M12 5v14" /><path d="M5 12h14" /></>);
export const QR = ({ size = 18 }: P) => svg(size, <><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3" /></>);
export const Server = ({ size = 18 }: P) => svg(size, <><rect x="3" y="4" width="18" height="7" rx="1" /><rect x="3" y="13" width="18" height="7" rx="1" /><path d="M7 8h.01M7 17h.01" /></>);
export const Timer = ({ size = 18 }: P) => svg(size, <><circle cx="12" cy="13" r="8" /><path d="M12 9v4l2 2M9 2h6" /></>);
export const Check = ({ size = 14 }: P) => svg(size, <path d="m5 12 5 5L20 7" />);
export const CheckCheck = ({ size = 14 }: P) => svg(size, <><path d="m2 12 5 5L17 7" /><path d="m12 17 10-10" /></>);
export const Clock = ({ size = 14 }: P) => svg(size, <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>);
export const Alert = ({ size = 14 }: P) => svg(size, <><circle cx="12" cy="12" r="9" /><path d="M12 8v4M12 16h.01" /></>);
export const File = ({ size = 22 }: P) => svg(size, <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><path d="M14 2v6h6" /></>);
export const Back = ({ size = 20 }: P) => svg(size, <path d="m15 18-6-6 6-6" />);
export const More = ({ size = 18 }: P) => svg(size, <><circle cx="12" cy="5" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="12" cy="19" r="1" /></>);
