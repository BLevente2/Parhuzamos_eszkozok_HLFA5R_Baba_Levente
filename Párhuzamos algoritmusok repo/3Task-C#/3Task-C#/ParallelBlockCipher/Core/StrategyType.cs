namespace ParallelBlockCipher.Core
{
    public enum StrategyType
    {
        SingleThreaded = 0,
        ParallelFor = 1,
        TaskBased = 2,
        AsyncAwait = 3
    }
}
