namespace TodoListClient.Models
{
    public class Todo
    {
        public int Id { get; set; }

        public string Title { get; set; }

        public string Owner { get; set; }

        internal bool IsInitialized()
        {
            return !string.IsNullOrEmpty(Title) && !string.IsNullOrEmpty(Owner);
        }
    }
}
