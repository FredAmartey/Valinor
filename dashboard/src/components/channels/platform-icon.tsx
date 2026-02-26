import { SlackLogo, WhatsappLogo, TelegramLogo } from "@phosphor-icons/react"

export function PlatformIcon({ platform, size = 16 }: { platform: string; size?: number }) {
  switch (platform) {
    case "slack":
      return <SlackLogo size={size} weight="fill" className="text-[#4A154B]" />
    case "whatsapp":
      return <WhatsappLogo size={size} weight="fill" className="text-[#25D366]" />
    case "telegram":
      return <TelegramLogo size={size} weight="fill" className="text-[#2AABEE]" />
    default:
      return null
  }
}
