namespace TodoListClient.Models
{
    public class Todo
    {
        public int Id { get; set; }

        public string Title { get; set; }

        public string Owner { get; set; }

        //Return true only if both Title and Owners are not empty strings 
        public bool IsInitialized()
        {
            return !string.IsNullOrEmpty(Title) && !string.IsNullOrEmpty(Owner);
        }
    }
}
