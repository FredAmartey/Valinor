"use client"

import { CONTACT_SECTION_URL, TECHNICAL_ARCHITECTURE_URL } from "@/lib/site-links"
import { useTheme, palette, RING_GRADIENT } from "./theme"

const FOOTER_LINKS = [
  { label: "Architecture", href: "/architecture" },
  { label: "Docs", href: TECHNICAL_ARCHITECTURE_URL },
  { label: "GitHub", href: "https://github.com/FredAmartey/heimdall" },
  { label: "Contact", href: CONTACT_SECTION_URL },
] as const

export function FooterCta() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <>
      {/* CTA band */}
      <section
        id="contact"
        className="py-32 flex flex-col items-center text-center px-6"
      >
        <h2
          className="text-3xl md:text-4xl font-semibold tracking-tight"
          style={{ color: c.textPri, transition: "color 0.5s ease" }}
        >
          Ready to trust AI agents with real access?
        </h2>
        <p
          className="mt-4 text-base max-w-[48ch]"
          style={{ color: c.textSec, transition: "color 0.5s ease" }}
        >
          Give broad-access agents the visibility, isolation, governance, and
          auditability real teams and enterprises need.
        </p>
        <button
          className="relative cursor-pointer border-none bg-transparent p-0 mt-10"
          style={{ borderRadius: 16 }}
        >
          <div
            className="absolute inset-0 rounded-[16px] overflow-hidden"
            style={{ opacity: 0.9 }}
          >
            <div
              className="absolute animate-[spin-ring_10s_linear_infinite]"
              style={{
                width: "200%",
                height: "200%",
                top: "-50%",
                left: "-50%",
                background: RING_GRADIENT,
                willChange: "transform",
              }}
            />
          </div>
          <div
            className="relative rounded-[14px] px-10 py-4 text-base font-medium tracking-tight"
            style={{
              background: c.plate,
              color: c.textPri,
              margin: 2,
              transition: "background 0.5s ease, color 0.5s ease",
            }}
          >
            Request a Demo
          </div>
        </button>

        <a
          href="/architecture"
          className="mt-4 text-sm font-medium no-underline hover:underline"
          style={{ color: c.textMuted, transition: "color 0.3s ease" }}
        >
          Read the architecture
        </a>
      </section>

      {/* Footer */}
      <footer className="py-10 px-6">
        <div className="mx-auto max-w-[1200px] flex flex-col md:flex-row items-center justify-between gap-4">
          <span
            className="text-sm font-semibold"
            style={{ color: c.textSec }}
          >
            Heimdall
          </span>
          <div className="flex gap-6">
            {FOOTER_LINKS.map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="text-sm no-underline hover:underline"
                style={{ color: c.textMuted, transition: "color 0.3s ease" }}
                {...(link.href.startsWith("https://")
                  ? { target: "_blank", rel: "noreferrer" }
                  : {})}
              >
                {link.label}
              </a>
            ))}
          </div>
          <span className="text-xs" style={{ color: c.textMuted }}>
            &copy; {new Date().getFullYear()} Heimdall. All rights reserved.
          </span>
        </div>
      </footer>
    </>
  )
}
