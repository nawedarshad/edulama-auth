const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
    console.log("--- Inspecting USERNAME Identities ---");
    const identities = await prisma.authIdentity.findMany({
        where: { type: 'USERNAME' },
        take: 10,
        include: { 
            school: { select: { name: true, code: true } },
            user: { select: { name: true } }
        }
    });

    if (identities.length === 0) {
        console.log("No USERNAME identities found.");
    } else {
        console.table(identities.map(id => ({
            value: id.value,
            school: id.school?.name || 'N/A',
            schoolCode: id.school?.code || 'N/A',
            userName: id.user?.name || 'N/A'
        })));
    }

    // Also check for a specific school to see if codes match
    const schools = await prisma.school.findMany({
        take: 5,
        select: { id: true, name: true, code: true }
    });
    console.log("\n--- Sample Schools ---");
    console.table(schools);

    await prisma.$disconnect();
}

main().catch(console.error);
