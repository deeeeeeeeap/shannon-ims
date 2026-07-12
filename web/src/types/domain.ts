export type AppError = {
  message: string
  status?: number
  method?: string
  url?: string
  code?: string
}

export type ServiceSuccess<T> = {
  ok: true
  data: T
}

export type ServiceFailure = {
  ok: false
  error: AppError
}

export type ServiceResult<T> = ServiceSuccess<T> | ServiceFailure

export type DomainStoreState = {
  loading: boolean
  lastOkAt: number | null
  error: AppError | null
}

export function ok<T>(data: T): ServiceSuccess<T> {
  return { ok: true, data }
}

export function fail(error: AppError): ServiceFailure {
  return { ok: false, error }
}

export function emptyState(): DomainStoreState {
  return { loading: false, lastOkAt: null, error: null }
}
