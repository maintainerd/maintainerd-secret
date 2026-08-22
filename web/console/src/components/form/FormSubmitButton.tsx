import { Button } from '@/components/ui/button'
import { Loader2 } from 'lucide-react'
import { cn } from '@/lib/utils'

interface FormSubmitButtonProps {
  isSubmitting: boolean
  submitText: string
  submittingText?: string
  disabled?: boolean
  className?: string
  /**
   * The id of the `<form>` this button submits.
   *
   * Auth's copy has no such prop because its forms are full pages, where the
   * submit sits inside the form element. Almost every form in this console lives
   * in a dialog whose actions belong in `DialogFooter` — outside the `<form>` in
   * the DOM — so the association has to be explicit or the button submits
   * nothing.
   */
  form?: string
}

export default function FormSubmitButton({
  isSubmitting,
  submitText,
  submittingText,
  disabled = false,
  className,
  form,
}: FormSubmitButtonProps) {
  const defaultSubmittingText = `${submitText.replace(/^(Create|Update|Add|Save|Delete)/, '$1ing')}...`
  const displaySubmittingText = submittingText || defaultSubmittingText

  return (
    <Button
      type="submit"
      form={form}
      disabled={isSubmitting || disabled}
      className={cn('gap-2', className)}
    >
      {isSubmitting && <Loader2 className="h-4 w-4 animate-spin" />}
      {isSubmitting ? displaySubmittingText : submitText}
    </Button>
  )
}
