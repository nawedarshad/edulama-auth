const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function diagnose() {
    const email = 'nawedarshad25@gmail.com';
    console.log(`--- Diagnosing email: ${email} ---`);

    // 1. Find all identities with this value
    const identities = await prisma.authIdentity.findMany({
        where: { value: { equals: email, mode: 'insensitive' } },
        include: { user: true }
    });

    console.log(`Found ${identities.length} identities:`);
    identities.forEach(id => {
        console.log(`  - Type: ${id.type}, UserID: ${id.userId}, Verified: ${id.verified}`);
    });

    // 2. Find all users linked to these identities or having this email in some field
    const userIds = [...new Set(identities.map(id => id.userId))];

    for (const userId of userIds) {
        const user = await prisma.user.findUnique({
            where: { id: userId },
            include: {
                userSchools: { include: { school: true, role: true } },
                school: true,
                role: true
            }
        });

        console.log(`\nUserID: ${user.id}`);
        console.log(`  Name: ${user.name}`);
        console.log(`  Global SchoolID: ${user.schoolId} (${user.school?.name || 'none'})`);
        console.log(`  Global Role: ${user.role?.name || 'none'}`);
        console.log(`  Memberships count: ${user.userSchools.length}`);
        user.userSchools.forEach((m, i) => {
            console.log(`    [${i}] School: ${m.school.name} (Code: ${m.school.code}, Subdomain: ${m.school.subdomain}), Role: ${m.role.name}`);
        });
    }

    // 3. Search for ANY school with the code 'demo' to cross-reference
    const demoSchool = await prisma.school.findFirst({ where: { code: { equals: 'demo', mode: 'insensitive' } } });
    if (demoSchool) {
        console.log(`\nFound School 'demo': ID ${demoSchool.id}, Subdomain: ${demoSchool.subdomain}`);
        const memberships = await prisma.userSchool.findMany({ where: { schoolId: demoSchool.id }, include: { user: true } });
        console.log(`  Users in this school: ${memberships.length}`);
        memberships.forEach(m => {
            console.log(`    - UserID ${m.userId} (${m.user.name})`);
        });
    }

    await prisma.$disconnect();
}

diagnose().catch(console.error);
