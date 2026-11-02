/// Minimal async state holder driving Loading / Data / Error / Empty UI.
enum AsyncStatus { loading, success, failure }

/// Immutable snapshot of an asynchronous control plane query.
class AsyncValue<T> {
  const AsyncValue.loading()
      : status = AsyncStatus.loading,
        data = null,
        error = null;

  const AsyncValue.success(T this.data)
      : status = AsyncStatus.success,
        error = null;

  const AsyncValue.failure(Object this.error)
      : status = AsyncStatus.failure,
        data = null;

  final AsyncStatus status;
  final T? data;
  final Object? error;

  bool get isLoading => status == AsyncStatus.loading;
  bool get isSuccess => status == AsyncStatus.success;
  bool get isFailure => status == AsyncStatus.failure;
}
