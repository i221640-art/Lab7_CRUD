import java.util.Scanner;

/**
 * Simple console calculator.
 * Build and run with: javac Calculator.java && java Calculator
 */
public class Calculator {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.println("Simple Calculator: enter expressions like 3 + 4 or 'quit' to exit.");
        while (true) {
            System.out.print("> ");
            if (!sc.hasNext()) break;
            String token = sc.next();
            if (token.equalsIgnoreCase("quit") || token.equalsIgnoreCase("exit")) break;
            try {
                double a = Double.parseDouble(token);
                String op = sc.next();
                double b = Double.parseDouble(sc.next());
                double result = compute(a, b, op);
                System.out.printf("= %.6f%n", result);
            } catch (Exception e) {
                System.out.println("Invalid input. Format: <number> <op> <number>. e.g. 3 * 4");
                sc.nextLine(); // clear rest of line
            }
        }
        sc.close();
        System.out.println("Bye.");
    }

    private static double compute(double a, double b, String op) {
        switch (op) {
            case "+": return a + b;
            case "-": return a - b;
            case "*": return a * b;
            case "/":
                if (b == 0) throw new ArithmeticException("Division by zero");
                return a / b;
            default:
                throw new IllegalArgumentException("Unsupported operator: " + op);
        }
    }
}
