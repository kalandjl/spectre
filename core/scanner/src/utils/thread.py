import signal
import threading
import time
import multiprocessing
from functools import wraps

class TimeoutError(Exception):
    """Raised when a function times out"""
    pass

def timeout_with_process(func, timeout_duration, *args, **kwargs):
    """
    Run a function with a timeout using multiprocessing.
    This version can actually terminate the function when it times out.
    
    Args:
        func: The function to run
        timeout_duration: Timeout in seconds
        *args: Arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
    
    Returns:
        The result of the function
    
    Raises:
        TimeoutError: If the function doesn't complete within the timeout
    """
    def wrapper(queue, func, args, kwargs):
        try:
            result = func(*args, **kwargs)
            queue.put(('result', result))
        except Exception as e:
            queue.put(('exception', e))
    
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=wrapper, args=(queue, func, args, kwargs))
    process.start()
    process.join(timeout_duration)
    
    if process.is_alive():
        # Process is still running, terminate it
        process.terminate()
        process.join()
        raise TimeoutError(f"Function timed out after {timeout_duration} seconds")
    
    if process.exitcode != 0:
        raise TimeoutError(f"Function process terminated with exit code {process.exitcode}")
    
    try:
        result_type, result_value = queue.get_nowait()
        if result_type == 'exception':
            raise result_value
        return result_value
    except:
        raise TimeoutError("Function completed but no result was returned")

def timeout(func, timeout_duration, *args, **kwargs):
    """
    Run a function with a timeout.
    
    Args:
        func: The function to run
        timeout_duration: Timeout in seconds
        *args: Arguments to pass to the function
        **kwargs: Keyword arguments to pass to the function
    
    Returns:
        The result of the function
    
    Raises:
        TimeoutError: If the function doesn't complete within the timeout
    """
    result = [None]
    exception = [None]
    completed = threading.Event()
    
    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e
        finally:
            completed.set()
    
    thread = threading.Thread(target=target)
    thread.daemon = False  # Don't use daemon threads
    thread.start()
    
    # Wait for completion or timeout
    if completed.wait(timeout_duration):
        # Function completed within timeout
        thread.join()  # Ensure thread is fully cleaned up
        if exception[0]:
            raise exception[0]
        return result[0]
    else:
        # Function timed out
        raise TimeoutError(f"Function timed out after {timeout_duration} seconds")
