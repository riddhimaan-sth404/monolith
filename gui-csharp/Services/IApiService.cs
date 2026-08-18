using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace MonolithGui.Services
{
    public interface IApiService
    {
        Task<T?> GetAsync<T>(string path);
        Task<byte[]?> GetBytesAsync(string path);
        Task<TResponse?> PostAsync<TRequest, TResponse>(string path, TRequest payload);
        Task<TResponse?> PutAsync<TRequest, TResponse>(string path, TRequest payload);
        Task<bool> DeleteAsync(string path);
        
        void ReconfigureHandler();
    }
}
