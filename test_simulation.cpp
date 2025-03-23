#include "simple_group.cpp"

int main() {
    SimpleGroup team_chat;
    
    // Alice sends first message
    team_chat.sendMessage("Alice", "Welcome to our secure chat!");
    
    // Bob responds
    team_chat.sendMessage("Bob", "Thanks Alice! Quantum-safe rocks!");
    
    return 0;
}
