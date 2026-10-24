const { validateTestDatabaseUrl } = require("../src/config");

describe("test database safety guard", () => {
    test("refuses the protected neondb database", () => {
        expect(() => validateTestDatabaseUrl(
            "postgresql://user:password@localhost:5432/neondb",
            "postgresql://user:password@localhost:5432/app"
        )).toThrow(/protected neondb database/i);
    });

    test("accepts a distinct test database", () => {
        expect(validateTestDatabaseUrl(
            "postgresql://user:password@localhost:5432/trustvault_test",
            "postgresql://user:password@localhost:5432/neondb"
        )).toBe("trustvault_test");
    });
});
