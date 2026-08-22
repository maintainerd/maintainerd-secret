import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 text-center">
      <div>
        <h1 className="text-xl font-semibold">Page not found</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          That address does not exist in this console.
        </p>
      </div>
      <Button asChild>
        <Link to="/browse">Back to secrets</Link>
      </Button>
    </div>
  )
}
