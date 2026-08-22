/**
 * Form Components Export Index
 * Central export point for all reusable form components.
 *
 * Adopted from maintainerd-auth's `components/form`. `FormDateField` and
 * `FormFileUploadField` are deliberately NOT carried over — this console has no
 * date-picker or upload surface, and the date field drags in react-day-picker
 * for nothing.
 */

// The shared field scaffold. Build new field components on this rather than
// re-implementing label/description/error/aria markup.
export { FieldShell } from './FieldShell'
export {
  fieldControlProps,
  resolveFieldId,
  FIELD_INVALID_CONTROL_CLASS,
  type FieldShellOwnProps,
} from './fieldControl'
export { FormInputField, type FormInputFieldProps } from './FormInputField'
export { FormTextareaField, type FormTextareaFieldProps } from './FormTextareaField'
export { FormPasswordField, type FormPasswordFieldProps } from './FormPasswordField'
export { FormSelectField, type FormSelectFieldProps, type SelectOption } from './FormSelectField'
export { FormCheckboxField, type FormCheckboxFieldProps } from './FormCheckboxField'
export { FormSwitchField, type FormSwitchFieldProps } from './FormSwitchField'
export { default as FormSubmitButton } from './FormSubmitButton'
export { default as FormSetupCard } from './FormSetupCard'
