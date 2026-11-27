export function BrandLogo({
  className = 'brand-logo-svg',
  size = 28,
}: {
  className?: string
  size?: number
}) {
  return (
    <svg
      aria-label="Proxy Sentinel"
      role="img"
      className={className}
      width={size}
      height={size}
      fill="none"
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path
        d="M16 3.5L5.5 7.5V14.5C5.5 20.8 10 26.4 16 28.5C22 26.4 26.5 20.8 26.5 14.5V7.5L16 3.5Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2.2"
      />
      <circle
        cx="16"
        cy="15"
        r="4.5"
        stroke="currentColor"
        strokeOpacity="0.45"
        strokeWidth="1.8"
      />
      <circle cx="16" cy="15" fill="currentColor" r="2" />
    </svg>
  )
}
