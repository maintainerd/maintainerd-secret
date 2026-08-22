import { Link } from 'react-router-dom'
import { FileQuestion } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { EmptyState } from '@/components/details'

export default function NotFoundPage() {
  return (
    <Card className="mx-auto w-full max-w-2xl">
      <CardContent>
        <EmptyState
          icon={FileQuestion}
          title="Page not found"
          description="That address does not exist in this console."
          action={
            <Button asChild size="sm">
              <Link to="/browse">Back to secrets</Link>
            </Button>
          }
        />
      </CardContent>
    </Card>
  )
}
