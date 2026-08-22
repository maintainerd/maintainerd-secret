/**
 * Composite input controls — the field components that are more than a labelled
 * control. Adopted from maintainerd-auth's `components/inputs`, minus the fields
 * that only exist for its domain (email, phone, password policy, file upload).
 */

export { CopyableCode } from './CopyableCode'
export { FormUrlField } from './FormUrlField'
export type { FormUrlFieldProps } from './FormUrlField'
export { FormSlugField } from './FormSlugField'
export type { FormSlugFieldProps } from './FormSlugField'
export { FormSearchableSelectField } from './FormSearchableSelectField'
export type {
  FormSearchableSelectFieldProps,
  SearchableSelectOption,
} from './FormSearchableSelectField'
export { SelectableOptionRow } from './SelectableOptionRow'
export type { SelectableOptionRowProps } from './SelectableOptionRow'
export { FormSwitchSubContainer } from './FormSwitchSubContainer'
export type { FormSwitchSubContainerProps } from './FormSwitchSubContainer'
export { FormCheckboxSubContainer } from './FormCheckboxSubContainer'
export type {
  FormCheckboxSubContainerProps,
  CheckboxSubContainerOption,
} from './FormCheckboxSubContainer'
