export function AuthDivider() {
  return (
    <div className="relative">
      <div className="absolute inset-0 flex items-center">
        <div className="w-full border-t border-zinc-200" />
      </div>
      <div className="relative flex justify-center text-xs">
        <span className="bg-white px-2 text-zinc-400">or continue with</span>
      </div>
    </div>
  )
}
